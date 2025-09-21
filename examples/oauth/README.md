# OAuth Integration Example

This example demonstrates OAuth2 integration with multiple providers including Google, GitHub, and custom enterprise SSO.

## Features Demonstrated

- ✅ Dynamic OAuth provider configuration
- ✅ Google OAuth2 integration
- ✅ GitHub OAuth2 integration
- ✅ Custom enterprise provider setup
- ✅ Automatic user creation from OAuth
- ✅ Mixed authentication (OAuth + traditional)
- ✅ Provider-aware user profiles

## Setup

### 1. Environment Variables (Optional)
For real OAuth testing, set these environment variables:

```bash
export GOOGLE_CLIENT_ID=your_google_client_id
export GOOGLE_CLIENT_SECRET=your_google_client_secret
export GITHUB_CLIENT_ID=your_github_client_id
export GITHUB_CLIENT_SECRET=your_github_client_secret
```

### 2. OAuth App Setup

**Google OAuth:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add `http://localhost:8080/auth/callback/google` to redirect URIs

**GitHub OAuth:**
1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create new OAuth App
3. Set Authorization callback URL to `http://localhost:8080/auth/callback/github`

## Running the Example

```bash
cd examples/oauth
go mod tidy
go run main.go
```

## Testing OAuth Flows

### 1. View Available Providers
```bash
curl http://localhost:8080/providers
```

### 2. Start OAuth Flow
Visit these URLs in your browser:
- `http://localhost:8080/auth/google` - Google OAuth
- `http://localhost:8080/auth/github` - GitHub OAuth
- `http://localhost:8080/auth/company-sso` - Custom provider

### 3. Traditional Authentication (Also Available)
```bash
# Sign up with email/password
curl -X POST http://localhost:8080/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Password123"}'

# Sign in with email/password
curl -X POST http://localhost:8080/signin \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com","password":"Password123"}'
```

## Provider Configuration

This example shows three types of OAuth providers:

1. **Built-in Helper (Google)**:
   ```go
   "google": auth.NewGoogleOAuthProvider(clientID, secret, callback)
   ```

2. **Built-in Helper (GitHub)**:
   ```go
   "github": auth.NewGitHubOAuthProvider(clientID, secret, callback)
   ```

3. **Custom Enterprise Provider**:
   ```go
   "company-sso": auth.NewCustomOAuthProvider(
       clientID, secret, callback,
       "https://sso.company.com/oauth2/authorize",
       "https://sso.company.com/oauth2/token",
       []string{"profile", "email", "groups"},
   )
   ```

## Key Features

- **Provider Flexibility**: Easily add any OAuth2-compliant provider
- **User Unification**: OAuth users automatically linked to existing accounts by email
- **Profile Information**: OAuth provider info stored with user
- **Fallback Authentication**: Traditional email/password still available
- **Security**: CSRF protection with state parameter validation