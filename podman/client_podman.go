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
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type PodmanClient struct {
	client  *http.Client
	baseURL string
}

func NewPodmanClient(config *PodmanProviderConfig) *PodmanClient {
	return &PodmanClient{
		client:  config.HTTPClient,
		baseURL: config.BaseURL,
	}
}

func newPodmanHTTPClient(uri string) (*http.Client, string, error) {
	if after, ok := strings.CutPrefix(uri, "unix://"); ok {
		socketPath := after

		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					//nolint:noctx // Unix socket connections don't need context cancellation
					return net.Dial("unix", socketPath)
				},
			},
		}, "http://d", nil
	}

	if strings.HasPrefix(uri, "tcp://") || strings.HasPrefix(uri, "http://") {
		return &http.Client{}, uri, nil
	}

	return nil, "", fmt.Errorf("unsupported podman URI scheme: %s", uri)
}

func (c *PodmanClient) doRequest(
	ctx context.Context,
	method, path string,
	body io.Reader,
) (*http.Response, error) {
	reqURL := c.baseURL + "/v5.0.0/libpod" + path

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.client.Do(req) //nolint:gosec // reqURL is constructed from baseURL + constant path
}

func (c *PodmanClient) BuildImage(ctx context.Context, opts ImageBuildOpts) error {
	tflog.Info(ctx, "Building image", map[string]any{
		"name":    opts.Tag,
		"context": opts.ContextDir,
	})

	contextTar, err := tarDirectory(opts.ContextDir)
	if err != nil {
		return fmt.Errorf("could not create context archive: %w", err)
	}

	params := url.Values{}
	params.Set("t", opts.Tag)
	params.Set("platform", "linux/"+runtime.GOARCH)

	if opts.Pull {
		params.Set("pull", "always")
	} else {
		params.Set("pull", "never")
	}

	for k, v := range opts.BuildArgs {
		params.Add("buildargs", fmt.Sprintf(`{%q:%q}`, k, v))
	}

	reqURL := c.baseURL + "/v5.0.0/libpod/build?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, contextTar)
	if err != nil {
		return fmt.Errorf("could not create build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-tar")

	resp, err := c.client.Do( //nolint:gosec // reqURL is constructed from baseURL + constant path
		req,
	)
	if err != nil {
		return fmt.Errorf("could not build image %s: %w", opts.Tag, err)
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	for decoder.More() {
		var event map[string]any

		decodeErr := decoder.Decode(&event)
		if decodeErr != nil {
			break
		}

		if errMsg, ok := event["error"].(string); ok && errMsg != "" {
			return fmt.Errorf("could not build image %s: %s", opts.Tag, errMsg)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"could not build image %s: unexpected status %d",
			opts.Tag,
			resp.StatusCode,
		)
	}

	return nil
}

func (c *PodmanClient) PushImage(
	ctx context.Context,
	name, username, password string,
) (string, error) {
	tflog.Info(ctx, "Pushing image to registry", map[string]any{"name": name})

	params := url.Values{}
	params.Set("destination", name)

	if username != "" && password != "" {
		params.Set("credentials", username+":"+password)
	}

	resp, err := c.doRequest(
		ctx,
		http.MethodPost,
		"/images/"+url.PathEscape(name)+"/push?"+params.Encode(),
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("could not push image %s: %w", name, err)
	}
	defer resp.Body.Close()

	var digest string

	decoder := json.NewDecoder(resp.Body)
	for decoder.More() {
		var event map[string]any

		decodeErr := decoder.Decode(&event)
		if decodeErr != nil {
			break
		}

		if errMsg, ok := event["error"].(string); ok && errMsg != "" {
			return "", fmt.Errorf("could not push image %s: %s", name, errMsg)
		}

		if d, ok := event["digest"].(string); ok && d != "" {
			digest = d
		}
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(
			"could not push image %s: unexpected status %d",
			name,
			resp.StatusCode,
		)
	}

	return digest, nil
}

func (c *PodmanClient) InspectImage(ctx context.Context, name string) (*ImageInspectResult, error) {
	tflog.Debug(ctx, "Inspecting image", map[string]any{"name": name})

	resp, err := c.doRequest(ctx, http.MethodGet, "/images/"+url.PathEscape(name)+"/json", nil)
	if err != nil {
		return nil, fmt.Errorf("could not inspect image %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not inspect image %s: status %d", name, resp.StatusCode)
	}

	var data struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
		Size        int64    `json:"Size"`
	}

	if decodeErr := json.NewDecoder(resp.Body).Decode(&data); decodeErr != nil {
		return nil, fmt.Errorf("could not decode inspect response for %s: %w", name, decodeErr)
	}

	result := &ImageInspectResult{
		ID:   data.ID,
		Size: data.Size,
	}

	if len(data.RepoDigests) > 0 {
		result.RepoDigest = data.RepoDigests[0]
	}

	return result, nil
}

func (c *PodmanClient) RemoveImage(ctx context.Context, name string) error {
	tflog.Debug(ctx, "Removing image", map[string]any{"name": name})

	resp, err := c.doRequest(ctx, http.MethodDelete, "/images/"+url.PathEscape(name), nil)
	if err != nil {
		return fmt.Errorf("could not remove image %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		return fmt.Errorf(
			"could not remove image %s: status %d: %s",
			name,
			resp.StatusCode,
			string(body),
		)
	}

	return nil
}

func (c *PodmanClient) ImageExists(ctx context.Context, name string) (bool, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/images/"+url.PathEscape(name)+"/exists", nil)
	if err != nil {
		return false, fmt.Errorf("could not check image existence %s: %w", name, err)
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusNoContent, nil
}

type ImageBuildOpts struct {
	BuildArgs  map[string]string
	Tag        string
	ContextDir string
	Pull       bool
}

type ImageInspectResult struct {
	ID         string
	RepoDigest string
	Size       int64
}

func tarDirectory(dir string) (io.Reader, error) {
	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	err = filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(absDir, path)
		if err != nil {
			return err
		}

		if relPath == "." {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		header.Name = relPath

		if writeErr := tw.WriteHeader(header); writeErr != nil {
			return writeErr
		}

		if info.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(tw, f)

		return err
	})
	if err != nil {
		return nil, err
	}

	if closeErr := tw.Close(); closeErr != nil {
		return nil, closeErr
	}

	return &buf, nil
}
