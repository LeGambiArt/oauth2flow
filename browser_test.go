package oauth2flow

import (
	"strings"
	"testing"
)

func TestOpenBrowser_SchemeValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		url          string
		expectScheme bool // true if error should mention scheme/https
	}{
		{
			name:         "valid https URL",
			url:          "https://accounts.google.com/auth?params=values",
			expectScheme: false,
		},
		{
			name:         "http scheme",
			url:          "http://example.com",
			expectScheme: true,
		},
		{
			name:         "javascript scheme",
			url:          "javascript:alert(1)",
			expectScheme: true,
		},
		{
			name:         "file scheme",
			url:          "file:///etc/passwd",
			expectScheme: true,
		},
		{
			name:         "ftp scheme",
			url:          "ftp://example.com",
			expectScheme: true,
		},
		{
			name:         "empty string",
			url:          "",
			expectScheme: false, // parse error, not scheme error
		},
		{
			name:         "invalid URL parse error",
			url:          "://broken",
			expectScheme: false, // parse error, not scheme error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := OpenBrowser(tt.url)

			//nolint:gocritic // if-else chain is clearer than switch for test validation logic
			if tt.expectScheme {
				// Should fail with scheme/https error
				if err == nil {
					t.Errorf("OpenBrowser(%q) error = nil, want error about https scheme", tt.url)
					return
				}
				errMsg := strings.ToLower(err.Error())
				if !strings.Contains(errMsg, "https") && !strings.Contains(errMsg, "scheme") {
					t.Errorf("OpenBrowser(%q) error = %v, want error containing 'https' or 'scheme'",
						tt.url, err)
				}
			} else if tt.url == "https://accounts.google.com/auth?params=values" {
				// Valid HTTPS URL may fail with platform-specific opener error
				// (e.g., "xdg-open not found"), which is acceptable - we're testing
				// scheme validation, not the actual opener
				if err != nil {
					errMsg := strings.ToLower(err.Error())
					// Error should NOT be about https/scheme
					if strings.Contains(errMsg, "https") || strings.Contains(errMsg, "scheme") {
						t.Errorf("OpenBrowser(%q) error = %v, want platform opener error (not scheme error)",
							tt.url, err)
					}
					// Otherwise it's a platform opener error, which is expected in test environment
				}
			} else {
				// Empty/invalid URL should fail with parse error (not scheme error)
				if err == nil {
					t.Errorf("OpenBrowser(%q) error = nil, want error", tt.url)
				}
			}
		})
	}
}
