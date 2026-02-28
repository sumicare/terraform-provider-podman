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
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write file %s: %v", path, err)
	}
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("failed to create directory %s: %v", path, err)
	}
}

func TestFindContainerfile(t *testing.T) {
	t.Run("finds Containerfile", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "Containerfile"), []byte("FROM scratch\n"))

		path, err := findContainerfile(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if filepath.Base(path) != "Containerfile" {
			t.Errorf("expected Containerfile, got %s", path)
		}
	})

	t.Run("falls back to Dockerfile", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"))

		path, err := findContainerfile(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if filepath.Base(path) != "Dockerfile" {
			t.Errorf("expected Dockerfile, got %s", path)
		}
	})

	t.Run("prefers Containerfile over Dockerfile", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "Containerfile"), []byte("FROM scratch\n"))
		writeFile(t, filepath.Join(dir, "Dockerfile"), []byte("FROM ubuntu\n"))

		path, err := findContainerfile(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if filepath.Base(path) != "Containerfile" {
			t.Errorf("expected Containerfile, got %s", path)
		}
	})

	t.Run("error when none found", func(t *testing.T) {
		dir := t.TempDir()

		_, err := findContainerfile(dir)
		if err == nil {
			t.Error("expected error when no Containerfile found")
		}
	})
}

func TestParseContainerfileSources(t *testing.T) {
	noVars := map[string]string{}

	t.Run("extracts COPY sources", func(t *testing.T) {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Containerfile")
		content := []byte(`FROM scratch
COPY go.mod go.sum ./
COPY main.go /app/
`)
		writeFile(t, cf, content)

		locals, gitRefs, err := parseContainerfileSources(cf, noVars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(gitRefs) != 0 {
			t.Errorf("expected no git refs, got %d", len(gitRefs))
		}

		expected := map[string]bool{"go.mod": true, "go.sum": true, "main.go": true}
		for _, p := range locals {
			if !expected[p] {
				t.Errorf("unexpected local path: %s", p)
			}

			delete(expected, p)
		}

		for p := range expected {
			t.Errorf("missing expected local path: %s", p)
		}
	})

	t.Run("skips multi-stage COPY --from", func(t *testing.T) {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Containerfile")
		content := []byte(`FROM golang:1.22 AS builder
COPY . .
FROM scratch
COPY --from=builder /app/binary /usr/local/bin/
COPY config.yaml /etc/
`)
		writeFile(t, cf, content)

		locals, _, err := parseContainerfileSources(cf, noVars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := map[string]bool{".": true, "config.yaml": true}
		for _, p := range locals {
			if !expected[p] {
				t.Errorf("unexpected local path: %s (should have skipped --from)", p)
			}

			delete(expected, p)
		}

		for p := range expected {
			t.Errorf("missing expected local path: %s", p)
		}
	})

	t.Run("detects ADD git URLs", func(t *testing.T) {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Containerfile")
		content := []byte(`FROM scratch
ADD git@github.com:org/repo.git#v1.0 /app/
ADD https://github.com/org/other.git#main:src /src/
`)
		writeFile(t, cf, content)

		locals, gitRefs, err := parseContainerfileSources(cf, noVars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(locals) != 0 {
			t.Errorf("expected no local paths, got %v", locals)
		}

		if len(gitRefs) != 2 {
			t.Fatalf("expected 2 git refs, got %d", len(gitRefs))
		}

		if gitRefs[0].URL != "git@github.com:org/repo.git" || gitRefs[0].Ref != "v1.0" {
			t.Errorf("unexpected git ref[0]: %+v", gitRefs[0])
		}

		if gitRefs[1].URL != "https://github.com/org/other.git" || gitRefs[1].Ref != "main" {
			t.Errorf("unexpected git ref[1]: %+v", gitRefs[1])
		}
	})

	t.Run("skips remote URLs", func(t *testing.T) {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Containerfile")
		content := []byte(`FROM scratch
ADD https://example.com/archive.tar.gz /tmp/
COPY local.txt /app/
`)
		writeFile(t, cf, content)

		locals, gitRefs, err := parseContainerfileSources(cf, noVars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(gitRefs) != 0 {
			t.Errorf("expected no git refs, got %d", len(gitRefs))
		}

		if len(locals) != 1 || locals[0] != "local.txt" {
			t.Errorf("expected [local.txt], got %v", locals)
		}
	})

	t.Run("handles line continuations", func(t *testing.T) {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Containerfile")
		writeFile(t, cf, []byte("FROM scratch\nCOPY a.txt \\\n     b.txt \\\n     /app/\n"))

		locals, _, err := parseContainerfileSources(cf, noVars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := map[string]bool{"a.txt": true, "b.txt": true}
		for _, p := range locals {
			delete(expected, p)
		}

		for p := range expected {
			t.Errorf("missing expected local path: %s", p)
		}
	})

	t.Run("handles JSON form", func(t *testing.T) {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Containerfile")
		content := []byte(`FROM scratch
COPY ["src/", "pkg/", "/app/"]
`)
		writeFile(t, cf, content)

		locals, _, err := parseContainerfileSources(cf, noVars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := map[string]bool{"src/": true, "pkg/": true}
		for _, p := range locals {
			delete(expected, p)
		}

		for p := range expected {
			t.Errorf("missing expected local path: %s", p)
		}
	})

	t.Run("interpolates ARG in ADD git URL", func(t *testing.T) {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Containerfile")
		content := []byte(`FROM scratch
ADD --keep-git-dir=false ${MY_REPO}#v${MY_VERSION} /build/app
`)
		writeFile(t, cf, content)

		vars := map[string]string{
			"MY_REPO":    "https://github.com/org/app.git",
			"MY_VERSION": "1.2.3",
		}

		locals, gitRefs, err := parseContainerfileSources(cf, vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(locals) != 0 {
			t.Errorf("expected no local paths, got %v", locals)
		}

		if len(gitRefs) != 1 {
			t.Fatalf("expected 1 git ref, got %d", len(gitRefs))
		}

		if gitRefs[0].URL != "https://github.com/org/app.git" {
			t.Errorf("expected interpolated URL, got %s", gitRefs[0].URL)
		}

		if gitRefs[0].Ref != "v1.2.3" {
			t.Errorf("expected ref v1.2.3, got %s", gitRefs[0].Ref)
		}
	})

	t.Run("unresolved vars kept as-is", func(t *testing.T) {
		dir := t.TempDir()
		cf := filepath.Join(dir, "Containerfile")
		content := []byte(`FROM scratch
COPY ${UNKNOWN}/file.txt /app/
`)
		writeFile(t, cf, content)

		locals, _, err := parseContainerfileSources(cf, noVars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(locals) != 1 || locals[0] != "${UNKNOWN}/file.txt" {
			t.Errorf("expected unresolved var preserved, got %v", locals)
		}
	})
}

func TestSplitGitRef(t *testing.T) {
	tests := []struct {
		input       string
		expectedURL string
		expectedRef string
	}{
		{"git@github.com:org/repo.git#v1.0", "git@github.com:org/repo.git", "v1.0"},
		{"https://github.com/org/repo.git#main:src", "https://github.com/org/repo.git", "main"},
		{"git@github.com:org/repo.git", "git@github.com:org/repo.git", "HEAD"},
		{"git://host/repo.git#feature/x", "git://host/repo.git", "feature/x"},
	}

	for _, tt := range tests {
		url, ref := splitGitRef(tt.input)
		if url != tt.expectedURL {
			t.Errorf("splitGitRef(%q) url = %q, want %q", tt.input, url, tt.expectedURL)
		}

		if ref != tt.expectedRef {
			t.Errorf("splitGitRef(%q) ref = %q, want %q", tt.input, ref, tt.expectedRef)
		}
	}
}

func TestIsGitURL(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"git@github.com:org/repo.git#v1", true},
		{"git://host/repo.git", true},
		{"https://github.com/org/repo.git#main", true},
		{"https://example.com/archive.tar.gz", false},
		{"./local/path", false},
		{"main.go", false},
	}

	for _, tt := range tests {
		result := isGitURL(tt.input)
		if result != tt.expected {
			t.Errorf("isGitURL(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestCollectVars(t *testing.T) {
	t.Run("collects ARG defaults", func(t *testing.T) {
		content := `ARG GOLANG_VERSION="1.26.0"
ARG REPO="repo.sumi.care"
ARG ORG="sumicare"
FROM ${REPO}/${ORG}/golang:${GOLANG_VERSION}
ARG APP_VERSION="1.0.0"
`
		vars := collectVars(content, nil)

		if vars["GOLANG_VERSION"] != "1.26.0" {
			t.Errorf("GOLANG_VERSION = %q, want 1.26.0", vars["GOLANG_VERSION"])
		}

		if vars["REPO"] != "repo.sumi.care" {
			t.Errorf("REPO = %q, want repo.sumi.care", vars["REPO"])
		}

		if vars["APP_VERSION"] != "1.0.0" {
			t.Errorf("APP_VERSION = %q, want 1.0.0", vars["APP_VERSION"])
		}
	})

	t.Run("build args override ARG defaults", func(t *testing.T) {
		content := `ARG VERSION="1.0.0"
`
		buildArgs := map[string]string{"VERSION": "2.0.0"}
		vars := collectVars(content, buildArgs)

		if vars["VERSION"] != "2.0.0" {
			t.Errorf("VERSION = %q, want 2.0.0", vars["VERSION"])
		}
	})

	t.Run("collects ENV values", func(t *testing.T) {
		content := `ARG MYVAR="from-arg"
ENV MYVAR=from-env
ENV LEGACY_VAR some-value
`
		vars := collectVars(content, nil)

		// ENV overrides ARG.
		if vars["MYVAR"] != "from-env" {
			t.Errorf("MYVAR = %q, want from-env", vars["MYVAR"])
		}

		if vars["LEGACY_VAR"] != "some-value" {
			t.Errorf("LEGACY_VAR = %q, want some-value", vars["LEGACY_VAR"])
		}
	})

	t.Run("ENV overrides build args", func(t *testing.T) {
		content := `ENV MYVAR=from-env
`
		buildArgs := map[string]string{"MYVAR": "from-build-arg"}
		vars := collectVars(content, buildArgs)

		if vars["MYVAR"] != "from-env" {
			t.Errorf("MYVAR = %q, want from-env", vars["MYVAR"])
		}
	})

	t.Run("skips bare ARG without default", func(t *testing.T) {
		content := `ARG NODEFAULT
ARG WITHDEFAULT="hello"
`
		vars := collectVars(content, nil)

		if _, exists := vars["NODEFAULT"]; exists {
			t.Error("bare ARG without default should not be in vars")
		}

		if vars["WITHDEFAULT"] != "hello" {
			t.Errorf("WITHDEFAULT = %q, want hello", vars["WITHDEFAULT"])
		}
	})

	t.Run("skips comments", func(t *testing.T) {
		content := `# ARG COMMENTED="yes"
ARG REAL="yes"
`
		vars := collectVars(content, nil)

		if _, exists := vars["COMMENTED"]; exists {
			t.Error("commented ARG should not be collected")
		}

		if vars["REAL"] != "yes" {
			t.Errorf("REAL = %q, want yes", vars["REAL"])
		}
	})
}

func TestSplitVarDecl(t *testing.T) {
	tests := []struct {
		input     string
		wantName  string
		wantValue string
	}{
		{`VERSION="1.0.0"`, "VERSION", "1.0.0"},
		{`VERSION=1.0.0`, "VERSION", "1.0.0"},
		{`VERSION='1.0.0'`, "VERSION", "1.0.0"},
		{`HOMEDIR=/build`, "HOMEDIR", "/build"},
		{`NODEFAULT`, "NODEFAULT", ""},
	}

	for _, tt := range tests {
		name, value := splitVarDecl(tt.input)
		if name != tt.wantName || value != tt.wantValue {
			t.Errorf("splitVarDecl(%q) = (%q, %q), want (%q, %q)",
				tt.input, name, value, tt.wantName, tt.wantValue)
		}
	}
}

func TestParseEnvDecl(t *testing.T) {
	t.Run("modern form", func(t *testing.T) {
		result := parseEnvDecl(`KEY1=val1 KEY2=val2`)
		if result["KEY1"] != "val1" || result["KEY2"] != "val2" {
			t.Errorf("unexpected result: %v", result)
		}
	})

	t.Run("legacy form", func(t *testing.T) {
		result := parseEnvDecl(`MY_KEY some value here`)
		if result["MY_KEY"] != "some value here" {
			t.Errorf("unexpected result: %v", result)
		}
	})

	t.Run("strips quotes", func(t *testing.T) {
		result := parseEnvDecl(`RUST_LOG="info"`)
		if result["RUST_LOG"] != "info" {
			t.Errorf("RUST_LOG = %q, want info", result["RUST_LOG"])
		}
	})
}

func TestInterpolateVars(t *testing.T) {
	vars := map[string]string{
		"REPO":    "https://github.com/org/app.git",
		"VERSION": "1.2.3",
		"HOMEDIR": "/build",
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"${REPO}#v${VERSION}", "https://github.com/org/app.git#v1.2.3"},
		{"$REPO#v$VERSION", "https://github.com/org/app.git#v1.2.3"},
		{"${HOMEDIR}/app", "/build/app"},
		{"${UNKNOWN}/file", "${UNKNOWN}/file"},
		{"no-vars-here", "no-vars-here"},
		{"", ""},
	}

	for _, tt := range tests {
		result := interpolateVars(tt.input, vars)
		if result != tt.expected {
			t.Errorf("interpolateVars(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	writeFile(t, path, []byte("hello world"))

	hash1, err := hashFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == "" {
		t.Error("expected non-empty hash")
	}

	// Same content produces same hash.
	hash2, err := hashFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("expected deterministic hash, got %s and %s", hash1, hash2)
	}

	// Different content produces different hash.
	writeFile(t, path, []byte("different content"))

	hash3, err := hashFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == hash3 {
		t.Error("expected different hash for different content")
	}
}

func TestHashDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), []byte("aaa"))
	writeFile(t, filepath.Join(dir, "b.txt"), []byte("bbb"))

	hash1, err := hashDirectory(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Deterministic.
	hash2, err := hashDirectory(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("expected deterministic hash, got %s and %s", hash1, hash2)
	}

	// Changes after modifying a file.
	writeFile(t, filepath.Join(dir, "a.txt"), []byte("modified"))

	hash3, err := hashDirectory(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == hash3 {
		t.Error("expected different hash after file modification")
	}
}

func TestHashDirectory_SkipsHiddenDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), []byte("aaa"))
	mkdirAll(t, filepath.Join(dir, ".git", "objects"))
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"))

	hash1, err := hashDirectory(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Modifying hidden dir should not change hash.
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/other\n"))

	hash2, err := hashDirectory(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 != hash2 {
		t.Error("hidden dir changes should not affect hash")
	}
}

func TestBuildContextHash(t *testing.T) {
	dir := t.TempDir()
	writeFile(t,
		filepath.Join(dir, "Containerfile"),
		[]byte("FROM scratch\nCOPY main.go /app/\n"),
	)
	writeFile(t, filepath.Join(dir, "main.go"), []byte("package main\n"))

	hash1, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == "" {
		t.Error("expected non-empty hash")
	}

	// Deterministic.
	hash2, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("expected deterministic hash, got %s and %s", hash1, hash2)
	}

	// Changes when referenced file changes.
	writeFile(t, filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"))

	hash3, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == hash3 {
		t.Error("expected different hash after source file change")
	}

	// Changes when Containerfile changes.
	writeFile(t,
		filepath.Join(dir, "Containerfile"),
		[]byte("FROM scratch\nCOPY main.go /app/\nRUN echo hi\n"),
	)

	hash4, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash3 == hash4 {
		t.Error("expected different hash after Containerfile change")
	}
}

func TestHashPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hello.txt"), []byte("hello"))
	writeFile(t, filepath.Join(dir, "a.go"), []byte("package a"))
	writeFile(t, filepath.Join(dir, "b.go"), []byte("package b"))
	writeFile(t, filepath.Join(dir, "c.txt"), []byte("text"))

	sub := filepath.Join(dir, "subdir")
	mkdirAll(t, sub)
	writeFile(t, filepath.Join(sub, "a.txt"), []byte("aaa"))
	writeFile(t, filepath.Join(sub, "b.txt"), []byte("bbb"))

	pkg := filepath.Join(dir, "pkg")
	mkdirAll(t, pkg)
	writeFile(t, filepath.Join(pkg, "main.go"), []byte("package main"))

	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"single_file", "hello.txt", false},
		{"directory", "subdir", false},
		{"glob_pattern", "*.go", false},
		{"glob_with_dir", "pkg", false},
		{"nonexistent", "does_not_exist", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := hashPath(dir, tt.pattern)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if h == "" {
				t.Error("expected non-empty hash")
			}
		})
	}
}

func TestHashFile_Nonexistent(t *testing.T) {
	_, err := hashFile("/tmp/definitely_does_not_exist_xyzzy")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestBuildContextHash_MultipleCopySources(t *testing.T) {
	dir := t.TempDir()
	writeFile(t,
		filepath.Join(dir, "Containerfile"),
		[]byte("FROM scratch\nCOPY a.txt b.txt /dst/\n"),
	)
	writeFile(t, filepath.Join(dir, "a.txt"), []byte("aaa"))
	writeFile(t, filepath.Join(dir, "b.txt"), []byte("bbb"))

	hash1, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Change one source → different hash.
	writeFile(t, filepath.Join(dir, "b.txt"), []byte("changed"))

	hash2, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == hash2 {
		t.Error("expected different hash when COPY source changes")
	}
}

func TestBuildContextHash_CopyDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "src")
	mkdirAll(t, sub)
	writeFile(t, filepath.Join(sub, "main.go"), []byte("package main"))
	writeFile(t,
		filepath.Join(dir, "Containerfile"),
		[]byte("FROM scratch\nCOPY src/ /app/\n"),
	)

	hash1, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == "" {
		t.Error("expected non-empty hash")
	}

	// Change a file in the directory → different hash.
	writeFile(t, filepath.Join(sub, "main.go"), []byte("package main\nfunc main(){}"))

	hash2, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == hash2 {
		t.Error("expected different hash when directory contents change")
	}
}

func TestBuildContextHash_WithBuildArgsLocalPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Containerfile"), []byte(`ARG SRC="src"
FROM scratch
COPY ${SRC}/ /app/
`))

	sub := filepath.Join(dir, "src")
	mkdirAll(t, sub)
	writeFile(t, filepath.Join(sub, "main.go"), []byte("package main"))

	alt := filepath.Join(dir, "alt")
	mkdirAll(t, alt)
	writeFile(t, filepath.Join(alt, "main.go"), []byte("package alt"))

	hash1, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Override build arg to point to different dir.
	hash2, err := BuildContextHash(t.Context(), dir, map[string]string{"SRC": "alt"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash1 == hash2 {
		t.Error("expected different hash when build arg changes COPY source path")
	}
}

func TestBuildContextHash_SkipsUnresolvablePath(t *testing.T) {
	// COPY references a path that doesn't exist → BuildContextHash should still succeed.
	dir := t.TempDir()
	writeFile(t,
		filepath.Join(dir, "Containerfile"),
		[]byte("FROM scratch\nCOPY nonexistent /app/\nCOPY real.txt /app/\n"),
	)
	writeFile(t, filepath.Join(dir, "real.txt"), []byte("exists"))

	hash, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash even with unresolvable path")
	}
}

func TestBuildContextHash_GlobCopySource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t,
		filepath.Join(dir, "Containerfile"),
		[]byte("FROM scratch\nCOPY *.go /app/\n"),
	)
	writeFile(t, filepath.Join(dir, "a.go"), []byte("package a"))
	writeFile(t, filepath.Join(dir, "b.go"), []byte("package b"))

	hash, err := BuildContextHash(t.Context(), dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash for glob COPY")
	}
}

func TestBuildContextHash_ErrorNoContainerfile(t *testing.T) {
	dir := t.TempDir()

	_, err := BuildContextHash(t.Context(), dir, nil)
	if err == nil {
		t.Error("expected error when no Containerfile exists")
	}
}
