# Juniper Routing Director MCP Server

This package provides the Juniper Routing Director MCP (Model Context Protocol) server, enabling AI assistants and applications to interact with Juniper's network management platform through a standardized interface.

## Features

- Device management and monitoring
- Configuration template deployment
- VPN service management
- Network topology visualization
- KPI monitoring and observability
- Customer and organization management

## Requirements

- Python 3.8 or higher
- Access to a Juniper Routing Director instance
- Valid authentication credentials
- Network connectivity to the Routing Director API

## Installation

### From Repository

1. Clone the repository:
   ```bash
   git clone git@eng-gitlab.juniper.net:iceberg/ask-paragon.git
   cd ask-paragon/mcp_setup
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Make the script executable (optional):
   ```bash
   chmod +x RoutingDirectorMCP.py
   ```

### From Package

1. Extract and install the package:
   ```bash
   tar -xvf routingdirectormcp-0.1.0.tar.gz
   cd routingdirectormcp-0.1.0
   pip install -r requirements.txt
   python setup.py install  # If setup.py exists
   ```

## Configuration

### Configuration File Setup

Create a JSON configuration file with the following structure:

```json
{
  "name": "RoutingDirectorMCP",
  "http_url": "https://your-routing-director.example.com",
  "org_id": "your-organization-uuid",
  "auth": {
    "type": "basic",
    "username": "your-username@company.com",
    "password": "your-password"
  },
   "openapi_spec": "<path-to-openapi-spec.json>",
   "components": ["ems", "active-assurance", ...]
}
```
P.S: `openapi_spec` and `components` are optional fields. `openapi_spec` is used to provide Routing Director's Openapi spec (json). If the user wishes to filter the openapi spec only for certain components, then the `components` field can be used to provide a list of components to filter the spec.



### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Identifier for the MCP server instance |
| `http_url` | Yes | Base URL of your Routing Director instance |
| `org_id` | Yes | Organization UUID from your Routing Director setup |
| `auth.type` | Yes | Authentication method (currently supports "basic") |
| `auth.username` | Yes | Your Routing Director username |
| `auth.password` | Yes | Your Routing Director password |

### Getting Your Organization ID

1. Log into your Routing Director web interface
2. Navigate Settings(top right) -> System Setting -> Organisation ID -> Copy
3. Use this value for the `org_id` field

## Usage

### Starting the Server

```bash
python RoutingDirectorMCP.py -c /path/to/your/config.json
```

### Command Line Options

- `-H, --host`: MCP server host (default: 127.0.0.1)
- `-p, --port`: MCP server port (default: 30030)
- `-t, --transport`: MCP server transport (default: streamable-http, options: `streamable-http`, `stdio`)
- `-c, --config`: Path to the JSON configuration file (required)


## Available Tools/Functions

The MCP server exposes the following capabilities:

- **Organization Management**: List and manage organizations
- **Device Operations**: Retrieve device information, inventory, and configurations
- **Template Management**: Create, update, and deploy configuration templates
- **VPN Services**: Manage VPN instances and metrics
- **Network Topology**: Access topology data, nodes, links, and LSPs
- **Monitoring**: KPI data retrieval and custom metrics
- **Customer Management**: Customer data and relationship management

## Directory Structure

```
├── RoutingDirectorMCP.py          # Main server entry point
├── requirements.txt               # Python dependencies
├── utils/
│   ├── lm_calls/
│   │   ├── tools/                # Common tools shared between components
│   │   └── connection/           # Connection management module
│   └── mcp/                      # MCP server specific implementations
├── mcp_setup/
│   ├── README.md
│   ├── requirements.txt
│   ├── setup.py
│   └── cardinality-parser/
```

## Troubleshooting

### Common Issues

**Connection Errors:**
- Verify the `http_url` is correct and accessible
- Check network connectivity to the Routing Director instance
- Ensure firewall rules allow the connection

**Authentication Failures:**
- Verify username and password are correct
- Check if the account has necessary permissions
- Ensure the organization ID is valid

**Configuration Errors:**
- Validate JSON syntax in the configuration file
- Ensure all required fields are present
- Check file paths are correct and accessible

### Logging

Enable verbose logging to troubleshoot issues:

```bash
python RoutingDirectorMCP.py -c config.json -v
```

Log files are typically written to the current directory or system log location.

## Development

### Setting Up Development Environment

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install development dependencies:
   ```bash
   pip install -r mcp_setup/requirements.txt
   ```


## FastMCP Token Authentication

This project implements a file-based token authentication system for FastMCP servers. Authentication is enforced for HTTP-based transports (`streamable-http`) but **bypassed for `stdio` protocol** to enable local development and MCP client integration.

---

### Overview

#### Key Features

- **Dynamic Token Validation**: Tokens are validated on every request by reading from `.tokens` file
- **File-Based Storage**: Tokens are stored in `.tokens` (project root)
- **CLI Management**: Generate, list, show, and revoke tokens via command-line interface
- **Transport-Specific Auth**: Authentication is **bypassed for stdio**, enforced for HTTP transports

### Authentication Rules

| Transport | Authentication | Use Case |
|-----------|---------------|----------|
| `stdio` | ❌ Bypassed | Local development, MCP clients (Claude Desktop, etc.) |
| `streamable-http` | ✅ Enforced | Production HTTP deployments |


---


### Token Management

#### Generate a Token

```bash
python utils/mcp/token_cli.py generate --client-id sv@juniper.net --description "Token for SV"
```

**Output:**
```
Generated new token:
  ID: my-client
  Token: apa_CA98sH_VwEBd79aHA6O9NxbhXQN_RqaK
  Description: Production API

Save this token securely - it won't be shown again!
```

#### List All Tokens

```bash
python utils/mcp/token_cli.py list
```

**Output:**
```
ID                   Description                              Created
-------------------------------------------------------------------------------------
my-client            Production API                           2025-12-04T06:47:00.000000+00:00
test-client          Test Token                               2025-12-04T06:30:15.123456+00:00
```

#### Show Token Value

```bash
python utils/mcp/token_cli.py show --client-id my-client
```

**Output:**
```
Token ID: my-client
Token: apa_CA98sH_VwEBd79aHA6O9NxbhXQN_RqaK
Description: Production API
Created: 2025-12-04T06:47:00.000000+00:00
```

#### Revoke a Token

```bash
python utils/mcp/token_cli.py revoke --client-id my-client
```

**Output:**
```
Token 'my-client' has been revoked
```

---

#### Authentication Behavior

#### How It Works

1. **Server Startup**: Server checks `args.transport`
   - If `stdio`: `verifier = None` (no authentication)
   - If HTTP-based: `verifier = token_manager.get_verifier()`

2. **Request Validation** (HTTP only):
   - Extract `Authorization: Bearer <token>` header
   - `verify_token()` reads `.tokens` file
   - Match token, return `AccessToken` or `None`

3. **Dynamic Updates**:
   - Tokens added/revoked via CLI are immediately effective
   - No server restart required

#### Why stdio Bypasses Auth

The `stdio` transport is used by MCP clients like Claude Desktop, which communicate via standard input/output pipes in a local process. These clients:

- Run on the same machine as the server
- Cannot send HTTP headers
- Are inherently secure (local process isolation)

Therefore, authentication is unnecessary for `stdio` and would break MCP client integration.

---

### Testing Authentication

### 1. Start the Server

#### For HTTP Testing (Authentication Enabled)
```bash
python RoutingDirectorMCP.py -c config.json -t streamable-http -H 127.0.0.1 -p 8080
```

Expected log:
```
WARNING:mcp_server:No tokens found. All requests will be rejected until a token is generated via CLI.
```

#### For stdio Testing (Authentication Bypassed)
```bash
python RoutingDirectorMCP.py -c config.json -t stdio
```

Expected log:
```
INFO:mcp_server:Using stdio transport - authentication bypassed
```

---

### 2. Generate a Token

While the server is running (or before), generate a token:

```bash
python utils/mcp/token_cli.py generate --client-id test-user
```

Copy the token output (starts with `apa_`).

---

### 3. Test with cURL (HTTP Transport Only)

#### Test 1: Valid Token (Expect Success)

```bash
curl -v -X POST \
  -H "Authorization: Bearer [GENERATED-TOKEN-VALUE]" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {
        "name": "test-client",
        "version": "1.0.0"
      }
    }
  }' \
  http://localhost:8080/mcp
```

**Expected Response:**
- Status: `200 OK`
- Headers: `mcp-session-id: <session-id>`
- Body: MCP initialization response

#### Test 2: Invalid Token (Expect Failure)

```bash
curl -v -X POST \
  -H "Authorization: Bearer invalid_token_123" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "test", "version": "1.0.0"}
    }
  }' \
  http://localhost:8080/mcp
```

**Expected Response:**
- Status: `401 Unauthorized`
- Body:
  ```json
  {
    "error": "invalid_token",
    "error_description": "Authentication failed. The provided bearer token is invalid..."
  }
  ```

#### Test 3: Missing Authorization Header (Expect Failure)

```bash
curl -v -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {...}}' \
  http://localhost:8080/mcp
```

**Expected Response:**
- Status: `401 Unauthorized`

---

### 4. Test Dynamic Token Updates

This verifies that tokens added/revoked during server runtime are immediately effective.

#### Step 1: Start server with a token
```bash
python utils/mcp/token_cli.py generate --client-id dynamic-test
python RoutingDirectorMCP.py --config test_config.json --transport streamable-http --port 8080
```

#### Step 2: Test the token (should succeed)
```bash
curl -X POST \
  -H "Authorization: Bearer <TOKEN_FROM_STEP_1>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {...}}' \
  http://localhost:8080/mcp
```

#### Step 3: Revoke the token (server still running)
```bash
python utils/mcp/token_cli.py revoke --client-id dynamic-test
```

#### Step 4: Test the token again (should fail)
```bash
# Same curl command as Step 2
# Expected: 401 Unauthorized
```

#### Step 5: Generate a new token (server still running)
```bash
python utils/mcp/token_cli.py generate --client-id dynamic-test-2
```

#### Step 6: Test the new token (should succeed)
```bash
curl -v -X POST \
  -H "Authorization: Bearer [GENERATED-TOKEN-VALUE]" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {
        "name": "test-client",
        "version": "1.0.0"
      }
    }
  }' \
  http://localhost:8080/mcp
```

---

### 5. Test stdio (No Authentication)

#### Step 1: Start server with stdio
```bash
python RoutingDirectorMCP.py --config config.json --transport stdio
```

Expected log:
```
INFO:mcp_server:Using stdio transport - authentication bypassed
```

#### Step 2: Send MCP messages via stdin

The server will accept any MCP messages without authentication. MCP clients (like Claude Desktop) can connect directly.

**Note**: Manual testing via stdin is impractical. Instead, configure your MCP client (Claude Desktop) to use this server:

```json
{
  "mcpServers": {
    "routing-directory": {
      "command": "python",
      "args": ["ask-paragon/RoutingDirectorMCP.py", "--config", "config.json", "--transport", "stdio"]
    }
  }
}
```

---


## Security Considerations

1. **Never commit `.tokens` file**: Add to `.gitignore`
2. **Use HTTPS in production**: HTTP transports send tokens in plaintext
3. **Rotate tokens regularly**: Use `revoke` + `generate` commands
4. **Limit token scopes**: Currently all tokens have full access (future enhancement)
5. **stdio is local-only**: Only use stdio transport for local MCP clients



## Support

For support and documentation:
- Internal Juniper documentation
- Contact the development team
- Check the project's issue tracker

## License

See `LICENSE` file for licensing details.

## Changelog

### Version 0.1.0
- Initial release
- Basic MCP server functionality
- Support for core Routing Director operations