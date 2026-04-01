# Routing Director MCP Server

An MCP (Model Context Protocol) server that integrates with Juniper's Routing Director platform, providing intelligent access to network routing, assurance, optimization, and intelligence capabilities.

## Features

- Flexible Authentication: Supports both basic and token-based authentication
- Multiple Transport Options: HTTP and stdio transport protocols
- Device management and monitoring
- Configuration template deployment
- VPN service management
- Network topology visualization
- KPI monitoring and observability
- Customer and organization management


## Prerequisites

- Python 3.10 or 3.11
- Juniper Routing Director instance
- Network connectivity to Routing Director API
- Valid Routing Director credentials (username/password or API token)

## Installation

### From Source

```bash
git clone https://github.com/Juniper/routing-director-mcp-server.git
cd routing-director-mcp-server
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### From MCP Registry

TBD 

## Configuration

### Configuration File (config.json)

Create a `config.json` file with the following structure:

**Basic Authentication:**
```json
{
  "http_url": "https://your-routing-director-host/",
  "org_id": "your-organization-id",
  "auth": {
    "type": "basic",
    "username": "your-username@example.com",
    "password": "your-password"
  }
}
```

**Token Authentication:**
```json
{
  "http_url": "https://your-routing-director-host/",
  "org_id": "your-organization-id",
  "auth": {
    "type": "token",
    "token": "your-api-token"
  }
}
```

Note: This authentication is between the MCP server and the Routing Director instance. The MCP server will handle authentication with Routing Director on behalf of clients connecting to it.

### Configuration Parameters

- **http_url** (required): URL of your Routing Director instance
- **org_id** (required): Your organization ID in Routing Director
- **auth** (required): Authentication configuration
  - **type**: Either `basic` or `token`
  - **username**: Routing Director username (for basic auth)
  - **password**: Routing Director password (for basic auth)
  - **token**: API token (for token auth)
- **components** (optional): Additional component configuration to filter tools and capabilities exposed by the MCP server. If the user wishes to filter the openapi spec only for certain components, then the `components` field can be used to provide a list of components to filter the spec.

Components can be one of the following:
- `ems` - For alarms related info (searching, ack and unack of alarms reported on Routing Director)
- `juniper-resiliency-interface` - For device syslog info (retrieving syslog messages collected on Routing Director)
- `device-kpi` - For fetching exception events related to Juniper Resiliency Interface (JRI) collected on Routing Director(forwarding, routing and os)


## Usage

### Starting the Server

```bash
python RoutingDirectorMCP.py --config config.json
```

### Command Line Options

```bash
python RoutingDirectorMCP.py --help
```

Available options:
- `-H, --host`: Server host (default: 127.0.0.1)
- `-p, --port`: Server port (default: 30030)
- `-t, --transport`: Transport type: `streamable-http` or `stdio` (default: streamable-http)
- `-c, --config`: Path to configuration file (required)
- `-v, --verbose`: Enable verbose logging


### Example: Start with Custom Configuration

```bash
python RoutingDirectorMCP.py \
  --config config.json \
  --host localhost \
  --port 8000 \
  --transport streamable-http \
  --verbose
```


## Authentication between the MCP Server and the MCP Host(Claude/Copilot etc)

### Token Management

The server supports token-based authentication through a token manager. If a tokens file exists, authentication is automatically enabled for HTTP transports.

For `stdio` transport, authentication is bypassed as it's typically used in secure local environments.

#### Enable authentication between MCP server and MCP client.  
You can use file-based token authentication for communication between an MCP client and MCP  
server. To generate a token, execute the following command in your local system:  
```bash
   python utils/mcp/token_cli.py generate --client-id sv@juniper.net --description "Token for SV"  
```

Where, 
client-id - is an ID that you use for generating the authentication token.  
The following is a sample of the generated output:  
```
Generated new token:  
 ID: my-client  
 Token: apa_CA98sH_VwEBd79aHA6O9NxbhXQN_RqaK  
 Description: Production API  
```
Save the generated token in a .tokens file. By default, the token is saved in the root directory of the GitHub MCP repository.  


### Logging

Enable detailed logging for debugging:

```bash
LOG_LEVEL=DEBUG python RoutingDirectorMCP.py --config config.json --verbose
```

### Connecting to the MCP Server

Users can use any MCP Host (like Claude, Copilot, Chatgpt, etc.) to connect to the MCP server. When configuring the MCP Host, use the same transport type, host, and port as specified when starting the MCP server. 

Configure Claude  
To configure Claude:  
1. Open the Claude configuration file in a text editor.  
• On a macOS machine, run the following command in the Terminal: `~/Library/Application Support/Claude/claude_desktop_config.json`
• On a Windows machine, open command prompt and enter: `%APPDATA%\Claude\claude_desktop_config.json`
2. Add your MCP server configuration as shown below:  
```json
      {  
       "mcpServers": {  
          "RoutingDirector": {  
             "command": "/Users/username/path-to-virtual-environment/.mcp_venv/bin/python",  
             "args": [ 
                "/Users/username/path-to-mcp-python-script/RoutingDirectorMCP.py", 
                "-c", 
                "/Users/username/path-to-config-json/config.json", 
                "-t", 
                "stdio"  
                ]  
             }  
          }  
      }  

``` 
3. Save the file.  
4. Restart Claude.
5. Verify the connection of Claude with MCP server.  

Claude is connected to the MCP server if the MCP server tools  are listed under + > Connectors.  


Configure Copilot : 
To configure Copilot:  
1. Open Virtual Studio (VS) code.  
Alternatively, you can use any other Integrated Development Environment (IDE) that supports  
Copilot and MCP server,  
2. Open the MCP settings file using one of the following methods:  
• On a macOS, run the following command in the Terminal: Open `~/Library/Application\ Support/Code/User/mcp.json` 
Where, user is your username on the macOS machine.  
• On a Windows machine, open command prompt and enter: `C:/Users/YourUserName/AppData/Roaming/Code/User/mcp.json`
Where, user is your username on the Windows machine.  
3. Add the MCP server configuration to the settings file as shown below:

```json
{  
     "mcpServers": {  
         "RoutingDirector": {  
         "command": "/Users/username/path-to-virtual-environment/.mcp_venv/bin/python",
         "args": [ 
               "/Users/username/path-to-mcp-python-script/RoutingDirectorMCP.py", 
               "-c", "/Users/username/path-to-config-json/config.json", 
               "-t", "stdio"  
            ]  
         }  
     }  
}  
```

4. Save the file.  
5. Close and reopen VS code for the MCP configuration changes to take effect.  
6. Verify that Copilot is connected with the MCP server.  
Copilot is connected to the MCP server if you find messages indicating successful connection to the  
MCP server in the Output panel of VS code.  
Alternatively, you can view MCP server tools (API calls) listed in VS code Extensions.



To ensure that the MCP server has started correctly, view the MCP server logs. The logs are  
generated based on the type of communication with the AI agent:  
• Starting MCP server 'Juniper Routing Directory' with transport 'stdio' if stdio is used.  
• INFO Starting MCP server 'Juniper Routing Directory' with transport 'http' on http://127.0.0.1:30030/mcp if  
streamable-http is used.  


For more details on configuring the MCP Servers in the MCP Host Apps , please refer 
VScode Copilot: https://code.visualstudio.com/docs/copilot/customization/mcp-servers 
Claude: https://code.claude.com/docs/en/mcp

---

## Troubleshooting

### Issue: "Config file path is required"
**Solution**: Ensure you provide the `--config` flag with a valid path to your configuration file.

### Issue: "Mandatory key missing in MCP config file"
**Solution**: Verify that your config.json includes all required keys: `http_url`, `org_id`, and `auth`.

### Issue: "Failed to authenticate"
**Solution**: 
- Verify your Routing Director credentials
- Ensure the Routing Director instance is accessible at the configured http_url
- Check that your username/password or API token is correct
- Verify network connectivity to the Routing Director host

### Issue: Connection Refused
**Solution**:
- Verify the server is running with `--host` and `--port` matching your client configuration
- Check firewall rules allow traffic on the configured port

### Issue: "No tokens file found. Authentication DISABLED"
**Solution**: For HTTP transports requiring authentication, ensure token files are properly initialized. For development/testing, this is typically acceptable.

---

## Version

Current version: **v2.9.0**

---

## Acknowledgments

This MCP server integrates with Juniper Networks' Routing Director platform, providing enterprise-grade network intelligence and optimization capabilities.

---