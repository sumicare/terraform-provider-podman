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

type gitRef struct {
	URL string
	Ref string
}

var varRefPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// collectVars parses ARG/ENV declarations and merges with buildArgs.
// Precedence: ENV > buildArgs > ARG defaults.
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

	vars := make(map[string]string, len(argDefaults)+len(envValues))
	maps.Copy(vars, argDefaults)

	maps.Copy(vars, buildArgs)
	maps.Copy(vars, envValues)

	return vars
}

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

func parseEnvDecl(s string) map[string]string {
	result := make(map[string]string)

	s = strings.TrimSpace(s)

	if !strings.Contains(s, "=") {
		parts := strings.SplitN(s, " ", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}

		return result
	}

	for field := range strings.FieldsSeq(s) {
		if idx := strings.Index(field, "="); idx > 0 {
			result[field[:idx]] = strings.Trim(field[idx+1:], `"'`)
		}
	}

	return result
}

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

// BuildContextHash computes a SHA256 over the Containerfile, all COPY/ADD
// referenced local files, and resolved git commit hashes for ADD git refs.
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

	h.Write(cfContent)
	h.Write([]byte("\x00"))

	sort.Strings(localPaths)

	for _, p := range localPaths {
		pathHash, hashErr := hashPath(absContext, p)
		if hashErr != nil {
			continue // skip paths that don't resolve (e.g. generated at build time)
		}

		fmt.Fprintf(h, "local:%s:%s\n", p, pathHash)
	}

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

func findContainerfile(contextDir string) (string, error) {
	for _, name := range []string{"Containerfile", "Dockerfile"} {
		p := filepath.Join(contextDir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("no Containerfile or Dockerfile found in %s", contextDir)
}

// parseContainerfileSources extracts local paths (COPY) and git refs (ADD)
// from a Containerfile. Skips multi-stage COPY --from and interpolates vars.
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

func hasFlag(argStr, flagName string) bool {
	for part := range strings.FieldsSeq(argStr) {
		lower := strings.ToLower(part)
		if strings.HasPrefix(lower, "--"+flagName+"=") || lower == "--"+flagName {
			return true
		}
	}

	return false
}

func isGitURL(src string) bool {
	if strings.HasPrefix(src, "git@") || strings.HasPrefix(src, "git://") {
		return true
	}

	return strings.Contains(src, ".git") &&
		(strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://"))
}

func isRemoteURL(src string) bool {
	return strings.HasPrefix(src, "http://") ||
		strings.HasPrefix(src, "https://") ||
		strings.HasPrefix(src, "ftp://")
}

// splitGitRef splits "url#ref:subdir" → (url, ref). Defaults to "HEAD".
func splitGitRef(src string) (url, ref string) {
	if idx := strings.Index(src, "#"); idx > 0 {
		url = src[:idx]
		ref = src[idx+1:]

		if cidx := strings.Index(ref, ":"); cidx > 0 {
			ref = ref[:cidx]
		}
	} else {
		url = src
		ref = "HEAD"
	}

	return url, ref
}

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

// hashDirectory hashes a directory tree. Hidden directories are skipped.
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
