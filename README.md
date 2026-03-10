# oauth2flow

Go package for OAuth2 desktop authorization flows. Handles the browser
consent + local callback server pattern used by CLI tools to acquire
initial OAuth2 tokens.

## Usage

```go
import "github.com/LeGambiArt/oauth2flow"

tok, err := oauth2flow.Run(ctx, oauth2flow.Config{
    ClientCredentialsFile: "client-credentials.json",
    TokenFile:             "token.json",
    Scopes:                []string{"https://www.googleapis.com/auth/calendar"},
})
```

## How it works

1. Loads client ID/secret from the credentials JSON file
2. Starts a local HTTP server for the OAuth2 callback
3. Opens the browser to the consent URL
4. Waits for the authorization code via callback
5. Exchanges the code for a token
6. Saves the token to disk with 0600 permissions

## Token format

Tokens are saved as JSON compatible with Google's token format:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "refresh_token": "...",
  "expiry": "2026-01-01T00:00:00Z"
}
```

## Supported platforms

- Linux (`xdg-open`)
- macOS (`open`)

## License

GPLv3 - see [LICENSE](LICENSE).
