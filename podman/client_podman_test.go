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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestPodmanClient(handler http.Handler) *PodmanClient {
	server := httptest.NewServer(handler)

	return &PodmanClient{
		client:  server.Client(),
		baseURL: server.URL,
	}
}

func TestPodmanClient_ImageExists(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantExists bool
	}{
		{"true", http.StatusNoContent, true},
		{"false", http.StatusNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestPodmanClient(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						t.Errorf("expected GET, got %s", r.Method)
					}

					w.WriteHeader(tt.status)
				}),
			)

			exists, err := client.ImageExists(t.Context(), "localhost/test:latest")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if exists != tt.wantExists {
				t.Errorf("exists = %v, want %v", exists, tt.wantExists)
			}
		})
	}
}

func TestPodmanClient_InspectImage(t *testing.T) {
	client := newTestPodmanClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":          "sha256:abc123",
			"RepoDigests": []string{"localhost/test@sha256:abc123"},
			"Size":        int64(12345),
		})
	}))

	result, err := client.InspectImage(t.Context(), "localhost/test:latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID != "sha256:abc123" {
		t.Errorf("expected ID sha256:abc123, got %s", result.ID)
	}

	if result.RepoDigest != "localhost/test@sha256:abc123" {
		t.Errorf("expected RepoDigest localhost/test@sha256:abc123, got %s", result.RepoDigest)
	}

	if result.Size != 12345 {
		t.Errorf("expected Size 12345, got %d", result.Size)
	}
}

func TestPodmanClient_InspectImage_NotFound(t *testing.T) {
	client := newTestPodmanClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	_, err := client.InspectImage(t.Context(), "localhost/missing:latest")
	if err == nil {
		t.Error("expected error for missing image")
	}
}

func TestPodmanClient_RemoveImage(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		status  int
		wantErr bool
	}{
		{"success", `{"deleted":true}`, http.StatusOK, false},
		{"not_found", "image not found", http.StatusNotFound, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestPodmanClient(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodDelete {
						t.Errorf("expected DELETE, got %s", r.Method)
					}

					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.body))
				}),
			)

			err := client.RemoveImage(t.Context(), "localhost/test:latest")
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPodmanClient_PushImage(t *testing.T) {
	tests := []struct {
		name       string
		response   map[string]any
		wantDigest string
		wantErr    bool
	}{
		{"success", map[string]any{"digest": "sha256:pushed123"}, "sha256:pushed123", false},
		{"error", map[string]any{"error": "unauthorized"}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestPodmanClient(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						t.Errorf("expected POST, got %s", r.Method)
					}

					w.WriteHeader(http.StatusOK)

					err := json.NewEncoder(w).Encode(tt.response)
					if err != nil {
						t.Errorf("json encode error: %v", err)
					}
				}),
			)

			digest, err := client.PushImage(
				t.Context(),
				"registry.example.com/test:v1",
				"user",
				"pass",
			)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if digest != tt.wantDigest {
				t.Errorf("digest = %q, want %q", digest, tt.wantDigest)
			}
		})
	}
}

func TestPodmanClient_BuildImage(t *testing.T) {
	tests := []struct {
		response map[string]any
		name     string
		wantErr  bool
	}{
		{map[string]any{"stream": "Successfully built"}, "success", false},
		{map[string]any{"error": "Containerfile not found"}, "error", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestPodmanClient(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						t.Errorf("expected POST, got %s", r.Method)
					}

					_, _ = io.Copy(io.Discard, r.Body)

					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(tt.response)
				}),
			)

			err := client.BuildImage(t.Context(), ImageBuildOpts{
				Tag:        "localhost/myimage:v1",
				ContextDir: ".",
			})
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewPodmanHTTPClient(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		wantBaseURL string
		wantErr     bool
	}{
		{"unix", "unix:///run/podman/podman.sock", "http://d", false},
		{"tcp", "tcp://localhost:8080", "tcp://localhost:8080", false},
		{"unsupported", "ssh://user@host/run/podman/podman.sock", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, baseURL, err := newPodmanHTTPClient(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if client == nil {
				t.Error("expected non-nil client")
			}

			if baseURL != tt.wantBaseURL {
				t.Errorf("baseURL = %q, want %q", baseURL, tt.wantBaseURL)
			}
		})
	}
}
