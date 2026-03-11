package oauth2flow

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
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

func TestSaveToken_BasicFunctionality(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token.json")

	expiry := time.Now().Add(time.Hour)
	tok := &oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
		Expiry:       expiry,
	}

	err := SaveToken(tokenPath, tok)
	if err != nil {
		t.Fatalf("SaveToken() error = %v, want nil", err)
	}

	// Verify file exists
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("token file does not exist: %v", err)
	}

	// Verify file has 0600 permissions
	if info.Mode().Perm() != 0o600 {
		t.Errorf("token file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Read and verify content
	data, err := os.ReadFile(tokenPath) //nolint:gosec // reading test file in temp directory
	if err != nil {
		t.Fatalf("failed to read token file: %v", err)
	}

	var tj TokenJSON
	if err := json.Unmarshal(data, &tj); err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if tj.AccessToken != "test-access-token" {
		t.Errorf("AccessToken = %q, want %q", tj.AccessToken, "test-access-token")
	}
	if tj.RefreshToken != "test-refresh-token" {
		t.Errorf("RefreshToken = %q, want %q", tj.RefreshToken, "test-refresh-token")
	}
	if tj.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", tj.TokenType, "Bearer")
	}
	if tj.Expiry == "" {
		t.Error("Expiry is empty, want RFC3339 timestamp")
	}

	// Verify expiry can be parsed
	parsedExpiry, err := time.Parse(time.RFC3339, tj.Expiry)
	if err != nil {
		t.Errorf("Expiry is not valid RFC3339: %v", err)
	}
	// Allow 1 second difference due to rounding
	if parsedExpiry.Sub(expiry).Abs() > time.Second {
		t.Errorf("Expiry = %v, want %v", parsedExpiry, expiry)
	}
}

func TestSaveToken_CreatesParentDirectory(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "subdir", "nested", "token.json")

	tok := &oauth2.Token{
		AccessToken: "test-token",
	}

	err := SaveToken(tokenPath, tok)
	if err != nil {
		t.Fatalf("SaveToken() error = %v, want nil", err)
	}

	// Verify file exists
	if _, err := os.Stat(tokenPath); err != nil {
		t.Errorf("token file does not exist: %v", err)
	}

	// Verify parent directories were created
	parentDir := filepath.Dir(tokenPath)
	if _, err := os.Stat(parentDir); err != nil {
		t.Errorf("parent directory does not exist: %v", err)
	}
}

func TestSaveToken_ZeroExpiryOmitted(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token.json")

	tok := &oauth2.Token{
		AccessToken: "test-token",
		Expiry:      time.Time{}, // zero value
	}

	err := SaveToken(tokenPath, tok)
	if err != nil {
		t.Fatalf("SaveToken() error = %v, want nil", err)
	}

	// Read and verify expiry field is absent
	data, err := os.ReadFile(tokenPath) //nolint:gosec // reading test file in temp directory
	if err != nil {
		t.Fatalf("failed to read token file: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if _, ok := raw["expiry"]; ok {
		t.Error("expiry field is present in JSON, want omitted for zero time")
	}
}

func TestSaveToken_AtomicBehavior(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token.json")

	// First write
	tok1 := &oauth2.Token{
		AccessToken: "first-token",
	}
	err := SaveToken(tokenPath, tok1)
	if err != nil {
		t.Fatalf("SaveToken() first write error = %v, want nil", err)
	}

	// Verify no temp files remain
	tempFiles, err := filepath.Glob(filepath.Join(tmpDir, ".token-*.tmp"))
	if err != nil {
		t.Fatalf("failed to glob temp files: %v", err)
	}
	if len(tempFiles) > 0 {
		t.Errorf("found %d temp files after save, want 0: %v", len(tempFiles), tempFiles)
	}

	// Second write (overwrite)
	tok2 := &oauth2.Token{
		AccessToken: "second-token",
	}
	err = SaveToken(tokenPath, tok2)
	if err != nil {
		t.Fatalf("SaveToken() second write error = %v, want nil", err)
	}

	// Verify file contains new token
	data, err := os.ReadFile(tokenPath) //nolint:gosec // reading test file in temp directory
	if err != nil {
		t.Fatalf("failed to read token file: %v", err)
	}

	var tj TokenJSON
	if err := json.Unmarshal(data, &tj); err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if tj.AccessToken != "second-token" {
		t.Errorf("AccessToken = %q, want %q", tj.AccessToken, "second-token")
	}

	// Verify no temp files remain after overwrite
	tempFiles, err = filepath.Glob(filepath.Join(tmpDir, ".token-*.tmp"))
	if err != nil {
		t.Fatalf("failed to glob temp files: %v", err)
	}
	if len(tempFiles) > 0 {
		t.Errorf("found %d temp files after overwrite, want 0: %v", len(tempFiles), tempFiles)
	}
}

func TestSaveToken_PermissionsPreserved(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token.json")

	tok := &oauth2.Token{
		AccessToken: "test-token",
	}

	// First write
	err := SaveToken(tokenPath, tok)
	if err != nil {
		t.Fatalf("SaveToken() error = %v, want nil", err)
	}

	// Check permissions
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("first write permissions = %o, want 0600", info.Mode().Perm())
	}

	// Overwrite
	tok2 := &oauth2.Token{
		AccessToken: "new-token",
	}
	err = SaveToken(tokenPath, tok2)
	if err != nil {
		t.Fatalf("SaveToken() overwrite error = %v, want nil", err)
	}

	// Check permissions after overwrite
	info, err = os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat after overwrite failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("overwrite permissions = %o, want 0600", info.Mode().Perm())
	}
}
