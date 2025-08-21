# MCP HTTP STDIO Proxy

A specialized authentication proxy server that enables secure communication between Visual Studio Code and GitHub Enterprise Server (GHES) for GitHub Copilot features. This server acts as a bridge, handling OAuth authentication flows and proxying MCP (Model Context Protocol) requests.

## Overview

The MCP HTTP STDIO Proxy is designed to facilitate secure integration between VS Code and GitHub Enterprise Server environments. It provides:

- **OAuth 2.0/OpenID Connect authentication** with GHES
- **Request proxying** between VS Code and MCP servers
- **Session management** with automatic cleanup
- **Token handling** and secure storage
- **Multi-user support** with isolated environments

## Quick Start

### Prerequisites

- Go 1.20 or later
- GitHub App configured on your GitHub Enterprise Server
- Access to GitHub Enterprise Server instance

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kwacky1/mcp_http_stdio_proxy.git
   cd mcp_http_stdio_proxy
   ```

2. **Build the application:**
   ```bash
   go build -o mcp-proxy
   ```

3. **Configure environment variables:**
   ```bash
   cp .env.sample .env
   # Edit .env with your configuration
   ```

4. **Run the server:**
   ```bash
   ./mcp-proxy
   ```

The server will start on `http://localhost:8080` by default.

## Releases

### Automatic Releases

The repository is configured to automatically build and create releases when version tags are pushed:

```bash
git tag v1.0.2
git push origin v1.0.2
```

### Manual Release Creation

For existing tags or to manually trigger a release, you can use GitHub's manual workflow dispatch:

1. Go to the [Actions tab](../../actions/workflows/release.yml) in the repository
2. Click "Run workflow" 
3. Enter the tag name (e.g., `v1.0.0` or `v1.0.1`)
4. Click "Run workflow"

This is useful for:
- Creating releases for tags that existed before the workflow was added
- Re-creating releases if needed
- Testing the release process

## Configuration

The server uses environment variables for configuration. Copy `.env.sample` to `.env` and configure:

### Required Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_APP_ID` | Your GitHub App's numeric ID |
| `GITHUB_APP_SLUG` | Your GitHub App's URL-friendly name |
| `GITHUB_CLIENT_ID` | GitHub App client ID (e.g., Iv1.xxx) |
| `GITHUB_CLIENT_SECRET` | GitHub App client secret |
| `GITHUB_PRIVATE_KEY` | GitHub App private key content |
| `GITHUB_HOST` | GitHub Enterprise Server URL |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_HOST` | MCP proxy server URL | `http://localhost:8080` |
| `GITHUB_PERSONAL_ACCESS_TOKEN` | Bot token for unauthenticated requests | - |
| `GITHUB_PRIVATE_KEY_PATH` | Path to private key file (alternative to `GITHUB_PRIVATE_KEY`) | - |
| `GITHUB_WEBHOOK_SECRET` | Webhook secret for GitHub events | - |

### Example Configuration

```bash
GITHUB_APP_ID=123456
GITHUB_APP_SLUG=my-copilot-app
GITHUB_CLIENT_ID=Iv1.1234567890abcdef
GITHUB_CLIENT_SECRET=your_client_secret_here
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
...your private key content...
-----END RSA PRIVATE KEY-----"
GITHUB_HOST=https://github.company.com
MCP_HOST=https://your-server-url.com
```

## Usage

### VS Code Integration

1. **Configure VS Code** to use your proxy server URL
2. **Initiate authentication** through VS Code
3. **Authenticate** with your GHES credentials
4. The server handles all subsequent authentication and proxying automatically

### Authentication Flow

1. VS Code initiates OAuth authentication
2. Server redirects to GitHub Enterprise Server
3. User authenticates with GHES credentials  
4. GHES redirects back with authorization code
5. Server exchanges code for access token
6. Token is stored securely for future requests

### API Endpoints

The server provides several endpoints:

- `/.well-known/oauth-authorization-server` - OAuth discovery
- `/oauth/authorize` - OAuth authorization
- `/oauth/callback` - OAuth callback handler
- `/oauth/token` - Token exchange
- `/oauth/register` - Dynamic client registration

## Architecture

The proxy consists of four main components:

1. **HTTP Server** - Handles VS Code requests and OAuth endpoints
2. **Session Store** - Manages user sessions and tokens in memory
3. **Proxy Manager** - Creates and manages MCP server instances
4. **Authentication Handler** - Implements OAuth/OIDC flows with GHES

## Development

### Building from Source

```bash
# Install dependencies
go mod tidy

# Build
go build -o mcp-proxy

# Run with debug logging
./mcp-proxy
```

### Project Structure

```
├── main.go                 # Entry point and server setup
├── internal/
│   ├── auth/              # Authentication handlers
│   │   ├── handler.go     # OAuth/OIDC implementation
│   │   ├── github.go      # GitHub API integration
│   │   └── jwt.go         # JWT token handling
│   ├── proxy/             # MCP request proxying
│   └── session/           # Session management
├── SERVER.md              # Detailed server documentation
├── SERVER_GITHUB_APP.md   # GitHub App specific docs
└── .env.sample           # Environment configuration template
```

## Security Features

- **Secure token handling** and storage
- **Automatic session expiration**
- **Request authentication validation**
- **Isolated user environments**
- **Token scope control**

## Monitoring and Logging

The server provides detailed logging for:

- Authentication attempts and token exchanges
- Request proxying and session management
- Error conditions and security events
- Performance metrics and cleanup operations

## Documentation

For detailed information, see:

- [**SERVER.md**](SERVER.md) - Comprehensive server documentation
- [**SERVER_GITHUB_APP.md**](SERVER_GITHUB_APP.md) - GitHub App integration guide

## Best Practices

- Use HTTPS in production environments
- Configure proper token scopes for your use case
- Monitor session usage and implement rate limiting
- Regularly rotate tokens and audit access logs
- Ensure proper GHES connectivity and client configuration

## Troubleshooting

### Common Issues

1. **Authentication failures**
   - Check server logs for detailed error information
   - Verify GitHub App configuration and credentials
   - Ensure GHES connectivity and proper endpoints

2. **Token exchange errors**
   - Validate client ID and secret configuration
   - Check OAuth callback URL settings
   - Verify GitHub App permissions and scopes

3. **Proxy connection issues**
   - Confirm MCP server accessibility
   - Check session storage and token validity
   - Review request routing and authentication headers

### Getting Help

- Check server logs for detailed diagnostic information
- Verify all configuration settings are correct
- Ensure your GitHub Enterprise Server is accessible
- Validate VS Code client configuration

## License

This project is licensed under the terms specified in the repository.

## Contributing

Contributions are welcome! Please ensure proper testing and documentation for any changes.