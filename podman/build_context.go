/*





   Copyright 2026 Sumicare

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package podman

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// gitRef represents a git repository reference found in an ADD instruction.
type gitRef struct {
	URL string
	Ref string
}

// varRefPattern matches Dockerfile/Containerfile variable references in both
// ${VAR} and $VAR forms.
var varRefPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// collectVars parses ARG and ENV declarations from Containerfile content and
// merges them with the supplied buildArgs. Evaluation order:
//  1. ARG defaults are collected (last non-empty default wins).
//  2. buildArgs override any ARG default.
//  3. ENV values override both ARG defaults and buildArgs (last wins).
func collectVars(content string, buildArgs map[string]string) map[string]string {
	argDefaults := make(map[string]string)
	envValues := make(map[string]string)

	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		for strings.HasSuffix(line, "\\") {
			line = strings.TrimSuffix(line, "\\")
			i++

			if i >= len(lines) {
				break
			}

			line += " " + strings.TrimSpace(lines[i])
		}

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "ARG "):
			name, val := splitVarDecl(strings.TrimSpace(line[4:]))
			if name != "" && val != "" {
				argDefaults[name] = val
			}

		case strings.HasPrefix(upper, "ENV "):
			maps.Copy(envValues, parseEnvDecl(strings.TrimSpace(line[4:])))
		}
	}

	// Start with ARG defaults.
	vars := make(map[string]string, len(argDefaults)+len(envValues))
	maps.Copy(vars, argDefaults)

	// Build args override ARG defaults.
	maps.Copy(vars, buildArgs)

	// ENV values take final precedence.
	maps.Copy(vars, envValues)

	return vars
}

// splitVarDecl parses an ARG declaration: "KEY=VALUE" or bare "KEY".
// Surrounding quotes on the value are stripped.
func splitVarDecl(s string) (name, value string) {
	s = strings.TrimSpace(s)

	if idx := strings.Index(s, "="); idx > 0 {
		name = s[:idx]
		value = strings.Trim(s[idx+1:], `"'`)
	} else {
		name = s
	}

	return name, value
}

// parseEnvDecl parses an ENV declaration. Supported forms:
//   - ENV KEY=VALUE [KEY2=VALUE2 …]
//   - ENV KEY VALUE  (legacy single-variable form)
func parseEnvDecl(s string) map[string]string {
	result := make(map[string]string)

	s = strings.TrimSpace(s)

	if !strings.Contains(s, "=") {
		// Legacy form: ENV KEY VALUE
		parts := strings.SplitN(s, " ", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}

		return result
	}

	// Modern form: KEY=VALUE [KEY2=VALUE2 …]
	for field := range strings.FieldsSeq(s) {
		if idx := strings.Index(field, "="); idx > 0 {
			result[field[:idx]] = strings.Trim(field[idx+1:], `"'`)
		}
	}

	return result
}

// interpolateVars replaces ${VAR} and $VAR references in s using the supplied
// variable map. Unresolved references are left as-is.
func interpolateVars(s string, vars map[string]string) string {
	return varRefPattern.ReplaceAllStringFunc(s, func(match string) string {
		var name string
		if strings.HasPrefix(match, "${") {
			name = match[2 : len(match)-1]
		} else {
			name = match[1:]
		}

		if val, ok := vars[name]; ok {
			return val
		}

		return match
	})
}

// BuildContextHash computes a SHA256 hash of the build context. The hash
// includes the Containerfile content, all local files referenced by COPY/ADD
// instructions, and resolved commit hashes for any git-based ADD instructions.
// ARG/ENV declarations in the Containerfile are interpolated using buildArgs.
func BuildContextHash(
	ctx context.Context,
	contextDir string,
	buildArgs map[string]string,
) (string, error) {
	absContext, err := filepath.Abs(contextDir)
	if err != nil {
		return "", fmt.Errorf("resolving context dir: %w", err)
	}

	containerfile, err := findContainerfile(absContext)
	if err != nil {
		return "", fmt.Errorf("finding Containerfile: %w", err)
	}

	cfContent, err := os.ReadFile(containerfile)
	if err != nil {
		return "", fmt.Errorf("reading Containerfile: %w", err)
	}

	vars := collectVars(string(cfContent), buildArgs)

	localPaths, gitRefs, err := parseContainerfileSources(containerfile, vars)
	if err != nil {
		return "", fmt.Errorf("parsing Containerfile: %w", err)
	}

	h := sha256.New()

	// Hash Containerfile content.
	h.Write(cfContent)
	h.Write([]byte("\x00"))

	// Hash local paths (sorted for determinism).
	sort.Strings(localPaths)

	for _, p := range localPaths {
		pathHash, hashErr := hashPath(absContext, p)
		if hashErr != nil {
			continue // skip paths that don't resolve (e.g. generated at build time)
		}

		fmt.Fprintf(h, "local:%s:%s\n", p, pathHash)
	}

	// Resolve and hash git refs (sorted for determinism).
	sort.Slice(gitRefs, func(i, j int) bool {
		return gitRefs[i].URL+gitRefs[i].Ref < gitRefs[j].URL+gitRefs[j].Ref
	})

	for _, ref := range gitRefs {
		commitHash, resolveErr := resolveGitRef(ctx, ref.URL, ref.Ref)
		if resolveErr != nil {
			fmt.Fprintf(h, "git:%s#%s:unresolved\n", ref.URL, ref.Ref)

			continue
		}

		fmt.Fprintf(h, "git:%s#%s:%s\n", ref.URL, ref.Ref, commitHash)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// findContainerfile locates the Containerfile in the context directory,
// checking for "Containerfile" first, then "Dockerfile".
func findContainerfile(contextDir string) (string, error) {
	for _, name := range []string{"Containerfile", "Dockerfile"} {
		p := filepath.Join(contextDir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("no Containerfile or Dockerfile found in %s", contextDir)
}

// parseContainerfileSources parses a Containerfile and extracts local file
// paths from COPY instructions and git references from ADD instructions.
// Multi-stage COPY (--from=…) instructions are skipped. Variable references
// in source paths are interpolated using vars.
func parseContainerfileSources(
	containerfilePath string,
	vars map[string]string,
) ([]string, []gitRef, error) {
	f, err := os.Open(containerfilePath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var (
		localPaths []string
		gitRefs    []gitRef
	)

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		for strings.HasSuffix(line, "\\") {
			line = strings.TrimSuffix(line, "\\")

			if !scanner.Scan() {
				break
			}

			line += " " + strings.TrimSpace(scanner.Text())
		}

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		upper := strings.ToUpper(line)
		isCopy := strings.HasPrefix(upper, "COPY ")
		isAdd := strings.HasPrefix(upper, "ADD ")

		if !isCopy && !isAdd {
			continue
		}

		argStr := line[strings.Index(line, " ")+1:]

		// Skip multi-stage COPY --from=…
		if isCopy && hasFlag(argStr, "from") {
			continue
		}

		sources, _ := parseInstructionArgs(argStr)
		if len(sources) == 0 {
			continue
		}

		for _, src := range sources {
			src = interpolateVars(src, vars)

			if isGitURL(src) {
				u, ref := splitGitRef(src)

				gitRefs = append(gitRefs, gitRef{URL: u, Ref: ref})
			} else if !isRemoteURL(src) {
				localPaths = append(localPaths, src)
			}
		}
	}

	return localPaths, gitRefs, scanner.Err()
}

// parseInstructionArgs splits COPY/ADD arguments, skipping flags (--xxx=yyy).
// It returns source paths (all except the last arg, which is the destination)
// and the destination. Handles both shell form and JSON form.
func parseInstructionArgs(argStr string) (sources []string, dest string) {
	argStr = strings.TrimSpace(argStr)

	if strings.HasPrefix(argStr, "[") {
		return parseJSONArgs(argStr)
	}

	var parts []string

	for part := range strings.FieldsSeq(argStr) {
		if strings.HasPrefix(part, "--") {
			continue
		}

		parts = append(parts, part)
	}

	if len(parts) < 2 {
		return nil, ""
	}

	return parts[:len(parts)-1], parts[len(parts)-1]
}

// parseJSONArgs parses JSON-form COPY/ADD args: ["src1", "src2", "dest"].
func parseJSONArgs(argStr string) (sources []string, dest string) {
	argStr = strings.Trim(argStr, "[] ")

	var parts []string

	for p := range strings.SplitSeq(argStr, ",") {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "\"'")

		if p != "" {
			parts = append(parts, p)
		}
	}

	if len(parts) < 2 {
		return nil, ""
	}

	return parts[:len(parts)-1], parts[len(parts)-1]
}

// hasFlag checks if a --flag with the given name exists in the args string.
func hasFlag(argStr, flagName string) bool {
	for part := range strings.FieldsSeq(argStr) {
		lower := strings.ToLower(part)
		if strings.HasPrefix(lower, "--"+flagName+"=") || lower == "--"+flagName {
			return true
		}
	}

	return false
}

// isGitURL returns true if the source looks like a git repository reference.
func isGitURL(src string) bool {
	if strings.HasPrefix(src, "git@") || strings.HasPrefix(src, "git://") {
		return true
	}

	return strings.Contains(src, ".git") &&
		(strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://"))
}

// isRemoteURL returns true if the source is a remote URL (http/https/ftp).
func isRemoteURL(src string) bool {
	return strings.HasPrefix(src, "http://") ||
		strings.HasPrefix(src, "https://") ||
		strings.HasPrefix(src, "ftp://")
}

// splitGitRef splits a git URL#ref into the base URL and the ref.
// For example "git@github.com:org/repo.git#v1.0" → ("git@github.com:org/repo.git", "v1.0").
// The optional :subdir suffix on the ref is stripped.
func splitGitRef(src string) (url, ref string) {
	if idx := strings.Index(src, "#"); idx > 0 {
		url = src[:idx]
		ref = src[idx+1:]

		// Strip subdir from ref (format: ref:subdir).
		if cidx := strings.Index(ref, ":"); cidx > 0 {
			ref = ref[:cidx]
		}
	} else {
		url = src
		ref = "HEAD"
	}

	return url, ref
}

// resolveGitRef uses git ls-remote to resolve a git URL + ref to a commit hash.
func resolveGitRef(ctx context.Context, url, ref string) (string, error) {
	if ref == "" {
		ref = "HEAD"
	}

	cmd := exec.CommandContext(ctx, "git", "ls-remote", url, ref)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git ls-remote %s %s: %w", url, ref, err)
	}

	line := strings.TrimSpace(string(output))
	if line == "" {
		return "", fmt.Errorf("no matching ref %q in %s", ref, url)
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", fmt.Errorf("unexpected git ls-remote output for %s %s", url, ref)
	}

	return parts[0], nil
}

// hashPath computes a SHA256 hash of a file or directory relative to basePath.
// Glob patterns in relPath are expanded.
func hashPath(basePath, relPath string) (string, error) {
	fullPattern := filepath.Join(basePath, relPath)

	matches, err := filepath.Glob(fullPattern)
	if err != nil {
		return "", err
	}

	if len(matches) == 0 {
		fullPath := filepath.Join(basePath, relPath)

		info, statErr := os.Stat(fullPath)
		if statErr != nil {
			return "", statErr
		}

		if info.IsDir() {
			return hashDirectory(fullPath)
		}

		return hashFile(fullPath)
	}

	sort.Strings(matches)

	h := sha256.New()

	for _, match := range matches {
		info, statErr := os.Stat(match)
		if statErr != nil {
			continue
		}

		var pathHash string
		if info.IsDir() {
			pathHash, err = hashDirectory(match)
		} else {
			pathHash, err = hashFile(match)
		}

		if err != nil {
			continue
		}

		rel, _ := filepath.Rel(basePath, match)
		fmt.Fprintf(h, "%s:%s\n", rel, pathHash)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashFile computes the SHA256 hash of a single file's content.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, copyErr := io.Copy(h, f); copyErr != nil {
		return "", copyErr
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashDirectory computes a deterministic SHA256 hash of a directory tree.
// Hidden directories (starting with ".") are skipped.
func hashDirectory(dir string) (string, error) {
	h := sha256.New()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && d.Name() != "." {
			return filepath.SkipDir
		}

		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		fileHash, err := hashFile(path)
		if err != nil {
			return err
		}

		fmt.Fprintf(h, "%s:%s\n", rel, fileHash)

		return nil
	})
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
