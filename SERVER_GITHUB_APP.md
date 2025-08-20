# MCP Proxy Server Documentation

## Overview

The MCP Proxy Server is a specialized middleware component that enables secure authentication and communication between Visual Studio Code and GitHub Enterprise Server (GHES) for GitHub Copilot features. It acts as a bridge, handling OAuth authentication flows and proxying MCP (Model Context Protocol) requests between VS Code and the local MCP server.

## Key Features

### 1. Authentication Integration

- Implements OAuth 2.0/OpenID Connect flows for VS Code
- Handles GitHub Enterprise Server authentication
- Supports both session-based and token-based authentication
- Manages secure token exchange and storage

### 2. Request Proxying

- Proxies MCP requests between VS Code and the local MCP server
- Injects authentication tokens automatically into requests
- Maintains separate proxy instances for different users
- Handles both authenticated and unauthenticated tool requests

### 3. Session Management

- Maintains secure user sessions
- Handles session cleanup and token expiration
- Supports concurrent users with isolated MCP server instances
- Automatically cleans up inactive sessions

## Architecture

### Components

1. **HTTP Server**
   - Handles incoming requests from VS Code
   - Implements OAuth endpoints
   - Manages request routing and authentication

2. **Session Store**
   - In-memory session storage
   - Maps session IDs to user tokens
   - Maintains user-specific MCP server instances

3. **Proxy Manager**
   - Creates and manages MCP server instances
   - Handles stdio communication with MCP servers
   - Routes requests to appropriate server instances

4. **Authentication Handler**
   - Implements OAuth/OIDC flows
   - Handles token exchange with GHES
   - Manages authorization states

## Authentication Flow

1. VS Code initiates authentication via OAuth
2. Server redirects to GitHub Enterprise Server login
3. User authenticates with GHES credentials
4. GHES redirects back with authorization code
5. Server exchanges code for access token
6. Token is returned to VS Code for future requests

## Security Features

- Secure token handling and storage
- Automatic session expiration
- Request authentication validation
- Isolated user environments
- Token scope control

## Configuration

The server uses environment variables for configuration:

- `OAUTH_CLIENT_ID`: GitHub OAuth app client ID
- `OAUTH_CLIENT_SECRET`: GitHub OAuth app client secret
- `GITHUB_HOST`: GitHub Enterprise Server URL
- `MCP_HOST`: MCP proxy server URL
- `GITHUB_PERSONAL_ACCESS_TOKEN`: Optional bot token for unauthenticated requests

## Integration

### VS Code Integration

The server integrates with VS Code through:
- OAuth/OIDC discovery endpoints
- Token exchange endpoints
- MCP request proxying
- Bearer token authentication

### GitHub Enterprise Integration

Connects to GHES through:
- OAuth authentication
- API token exchange
- User information endpoints

## Usage

1. Deploy the server with appropriate configuration
2. Configure VS Code to use the server URL
3. Users authenticate through VS Code
4. Server handles authentication and proxying automatically

## Best Practices

- Use HTTPS in production
- Configure proper token scopes
- Monitor session usage
- Implement rate limiting
- Regular token rotation
- Audit logging

## Error Handling

- JSON-RPC compliant error responses
- Proper HTTP status codes
- Detailed error logging
- Authentication retry mechanisms

## Performance Considerations

- In-memory session storage for fast access
- Per-user MCP server instances
- Efficient proxy routing
- Automatic cleanup of inactive sessions

## Monitoring

The server provides logging for:
- Authentication attempts
- Token exchanges
- Request proxying
- Session management
- Error conditions

## Support

For issues or questions:
- Check server logs for detailed information
- Verify configuration settings
- Ensure GHES connectivity
- Check VS Code client configuration
