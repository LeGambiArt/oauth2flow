package oauth2flow

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateState(t *testing.T) {
	t.Parallel()

	state, err := generateState()
	if err != nil {
		t.Fatalf("generateState() error = %v, want nil", err)
	}

	// Verify output is exactly 32 characters (16 bytes hex-encoded)
	if len(state) != 32 {
		t.Errorf("generateState() length = %d, want 32", len(state))
	}

	// Verify output is valid hexadecimal
	decoded, err := hex.DecodeString(state)
	if err != nil {
		t.Errorf("generateState() produced invalid hex: %v", err)
	}

	// Verify decoded bytes are 16 bytes long
	if len(decoded) != 16 {
		t.Errorf("generateState() decoded length = %d bytes, want 16", len(decoded))
	}

	// Verify two consecutive calls produce different values (non-determinism)
	state2, err := generateState()
	if err != nil {
		t.Fatalf("generateState() second call error = %v, want nil", err)
	}
	if state == state2 {
		t.Errorf("generateState() produced identical values on consecutive calls: %s", state)
	}
}

func TestValidateEndpointURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		url       string
		field     string
		wantError bool
		errorText string
	}{
		{
			name:      "valid https URL",
			url:       "https://accounts.google.com/o/oauth2/auth",
			field:     "auth_uri",
			wantError: false,
		},
		{
			name:      "valid https URL with query params",
			url:       "https://example.com/path/to/endpoint?query=param",
			field:     "token_uri",
			wantError: false,
		},
		{
			name:      "empty string",
			url:       "",
			field:     "auth_uri",
			wantError: true,
			errorText: "empty",
		},
		{
			name:      "http scheme",
			url:       "http://example.com/auth",
			field:     "auth_uri",
			wantError: true,
			errorText: "https",
		},
		{
			name:      "javascript scheme",
			url:       "javascript:alert(1)",
			field:     "auth_uri",
			wantError: true,
			errorText: "https",
		},
		{
			name:      "ftp scheme",
			url:       "ftp://example.com",
			field:     "token_uri",
			wantError: true,
			errorText: "https",
		},
		{
			name:      "invalid URL parse error",
			url:       "://broken",
			field:     "auth_uri",
			wantError: true,
			errorText: "valid URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateEndpointURL(tt.url, tt.field)

			if tt.wantError {
				if err == nil {
					t.Errorf("validateEndpointURL(%q, %q) error = nil, want error containing %q",
						tt.url, tt.field, tt.errorText)
					return
				}
				errMsg := strings.ToLower(err.Error())
				if !strings.Contains(errMsg, strings.ToLower(tt.errorText)) {
					t.Errorf("validateEndpointURL(%q, %q) error = %v, want error containing %q",
						tt.url, tt.field, err, tt.errorText)
				}
			} else if err != nil {
				t.Errorf("validateEndpointURL(%q, %q) error = %v, want nil",
					tt.url, tt.field, err)
			}
		})
	}
}

func TestLoadClientCredentials_InstalledApp(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	credFile := filepath.Join(tmpDir, "credentials.json")

	//nolint:gosec // test fixture, not real credentials
	credJSON := `{
  "installed": {
    "client_id": "test-client-id.apps.googleusercontent.com",
    "client_secret": "test-secret-123",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}`

	if err := os.WriteFile(credFile, []byte(credJSON), 0o600); err != nil {
		t.Fatalf("failed to write test credentials: %v", err)
	}

	wantScopes := []string{"https://www.googleapis.com/auth/drive"}
	cfg, err := LoadClientCredentials(credFile, wantScopes)
	if err != nil {
		t.Fatalf("LoadClientCredentials() error = %v, want nil", err)
	}

	if cfg.ClientID != "test-client-id.apps.googleusercontent.com" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "test-client-id.apps.googleusercontent.com")
	}
	if cfg.ClientSecret != "test-secret-123" {
		t.Errorf("ClientSecret = %q, want %q", cfg.ClientSecret, "test-secret-123")
	}
	if cfg.Endpoint.AuthURL != "https://accounts.google.com/o/oauth2/auth" {
		t.Errorf("AuthURL = %q, want %q", cfg.Endpoint.AuthURL, "https://accounts.google.com/o/oauth2/auth")
	}
	if cfg.Endpoint.TokenURL != "https://oauth2.googleapis.com/token" {
		t.Errorf("TokenURL = %q, want %q", cfg.Endpoint.TokenURL, "https://oauth2.googleapis.com/token")
	}
	if len(cfg.Scopes) != 1 {
		t.Errorf("Scopes length = %d, want 1", len(cfg.Scopes))
	} else if cfg.Scopes[0] != wantScopes[0] { //nolint:gosec // wantScopes is a non-empty literal
		t.Errorf("Scopes[0] = %q, want %q", cfg.Scopes[0], wantScopes[0])
	}
}

func TestLoadClientCredentials_WebApp(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	credFile := filepath.Join(tmpDir, "credentials.json")

	//nolint:gosec // test fixture, not real credentials
	credJSON := `{
  "web": {
    "client_id": "web-client-id.apps.googleusercontent.com",
    "client_secret": "web-secret-456",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}`

	if err := os.WriteFile(credFile, []byte(credJSON), 0o600); err != nil {
		t.Fatalf("failed to write test credentials: %v", err)
	}

	cfg, err := LoadClientCredentials(credFile, nil)
	if err != nil {
		t.Fatalf("LoadClientCredentials() error = %v, want nil", err)
	}

	if cfg.ClientID != "web-client-id.apps.googleusercontent.com" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "web-client-id.apps.googleusercontent.com")
	}
	if cfg.ClientSecret != "web-secret-456" {
		t.Errorf("ClientSecret = %q, want %q", cfg.ClientSecret, "web-secret-456")
	}
}

func TestLoadClientCredentials_PublicClient(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	credFile := filepath.Join(tmpDir, "credentials.json")

	// Public client with empty client_secret (valid with PKCE)
	//nolint:gosec // test fixture, not real credentials
	credJSON := `{
  "installed": {
    "client_id": "public-client-id.apps.googleusercontent.com",
    "client_secret": "",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}`

	if err := os.WriteFile(credFile, []byte(credJSON), 0o600); err != nil {
		t.Fatalf("failed to write test credentials: %v", err)
	}

	cfg, err := LoadClientCredentials(credFile, nil)
	if err != nil {
		t.Fatalf("LoadClientCredentials() error = %v, want nil (public clients are valid)", err)
	}

	if cfg.ClientID != "public-client-id.apps.googleusercontent.com" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "public-client-id.apps.googleusercontent.com")
	}
	if cfg.ClientSecret != "" {
		t.Errorf("ClientSecret = %q, want empty string", cfg.ClientSecret)
	}
}

func TestLoadClientCredentials_ValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		json      string
		errorText string
	}{
		{
			name: "missing client_id",
			json: `{
  "installed": {
    "client_id": "",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}`,
			errorText: "client_id",
		},
		{
			name: "empty auth_uri",
			json: `{
  "installed": {
    "client_id": "test-id",
    "auth_uri": "",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}`,
			errorText: "auth_uri",
		},
		{
			name: "http auth_uri",
			json: `{
  "installed": {
    "client_id": "test-id",
    "auth_uri": "http://insecure.example.com/auth",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}`,
			errorText: "https",
		},
		{
			name: "empty token_uri",
			json: `{
  "installed": {
    "client_id": "test-id",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": ""
  }
}`,
			errorText: "token_uri",
		},
		{
			name: "http token_uri",
			json: `{
  "installed": {
    "client_id": "test-id",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "http://insecure.example.com/token"
  }
}`,
			errorText: "https",
		},
		{
			name: "missing installed and web",
			json: `{
  "other": {
    "client_id": "test-id"
  }
}`,
			errorText: "installed",
		},
		{
			name:      "invalid JSON",
			json:      `{"installed": {invalid json}`,
			errorText: "parse",
		},
		{
			name:      "empty file",
			json:      ``,
			errorText: "unexpected end",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()
			credFile := filepath.Join(tmpDir, "credentials.json")

			if err := os.WriteFile(credFile, []byte(tt.json), 0o600); err != nil {
				t.Fatalf("failed to write test credentials: %v", err)
			}

			_, err := LoadClientCredentials(credFile, nil)
			if err == nil {
				t.Errorf("LoadClientCredentials() error = nil, want error containing %q", tt.errorText)
				return
			}

			errMsg := strings.ToLower(err.Error())
			if !strings.Contains(errMsg, strings.ToLower(tt.errorText)) {
				t.Errorf("LoadClientCredentials() error = %v, want error containing %q", err, tt.errorText)
			}
		})
	}
}

func TestLoadClientCredentials_FileNotFound(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	credFile := filepath.Join(tmpDir, "nonexistent.json")

	_, err := LoadClientCredentials(credFile, nil)
	if err == nil {
		t.Error("LoadClientCredentials() error = nil, want error for nonexistent file")
	}
}
