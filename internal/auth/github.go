package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// getInstallations fetches all installations for the GitHub App
func (h *Handler) getInstallations(jwt string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v3/app/installations", h.config.GithubHost)
	log.Printf("Fetching installations from URL: %s", url)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get installations: %s - %s", resp.Status, string(body))
	}

	var installations []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&installations); err != nil {
		return nil, fmt.Errorf("parse response: %v", err)
	}

	return installations, nil
}

// getUserInstallations fetches installations accessible to the authenticated user
func (h *Handler) getUserInstallations(token string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v3/user/installations", h.config.GithubHost)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %v", err)
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", fmt.Sprintf("GitHub-App/%s", h.config.AppSlug))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user installations: %s - %s", resp.Status, string(body))
	}

	var result struct {
		TotalCount    int                      `json:"total_count"`
		Installations []map[string]interface{} `json:"installations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse response: %v", err)
	}

	return result.Installations, nil
}

// getInstallationToken exchanges a JWT for an installation access token
func (h *Handler) getInstallationToken(jwt string, installationID string) (string, error) {
	url := fmt.Sprintf("%s/api/v3/app/installations/%s/access_tokens", h.config.GithubHost, installationID)
	
	// Request specific permissions
	data := map[string]interface{}{
		"permissions": map[string]string{
			"metadata": "read",
			"contents": "write",
			"issues": "write",
			"pull_requests": "write",
			"members": "read", // Required for /user endpoint
		},
		"repository_ids": []int{}, // Empty array means all repositories
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", url, io.NopCloser(bytes.NewBuffer(jsonData)))
	if err != nil {
		return "", fmt.Errorf("create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("failed to get installation token: %s - %s", resp.Status, string(body))
	}

	var tokenResp struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse response: %v", err)
	}

	if tokenResp.Token == "" {
		return "", fmt.Errorf("no token in response: %s", string(body))
	}

	return tokenResp.Token, nil
}

// getUserInfo fetches information about the authenticated user
func (h *Handler) getUserInfo(token string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v3/user", h.config.GithubHost)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %v", err)
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", fmt.Sprintf("GitHub-App/%s", h.config.AppSlug))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s - %s", resp.Status, string(body))
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("parse response: %v", err)
	}

	return userInfo, nil
}