package oauth2flow

import (
	"encoding/hex"
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
