import os
SERVER_NAME = "Juniper Routing Director"
DEFAULT_OPEN_API_SPEC_PATH = 'jrd-2.8.0-mcp-spec.json'

MCP_EXTENSION_KEY = 'x-mcp-server'
MCP_EXTENSION_LEAF_KEY = 'x-mcp'

# If the user does not provide any components in the config.json, these default components will be used to filter
# the openapi spec for Routing Directory MCP server.
MCP_DEFAULT_COMPONENTS_LIST = ['device-kpi', 'service-orchestration', 'active-assurance', 'ems', 'juniper-resiliency-interface']


# For each of the listed component, the corresponding tag to be added to the openapi spec endpoints is defined here.
# The tags are added when we want to filter the openapi spec with its corresponding component.
MCP_COMPONENTS = {
    'device-kpi': {
        "tag": "device-kpi-mcp"
    },
    'service-orchestration': {
        "tag": "service-orchestration-mcp"
    },
    'active-assurance': {
        "tag": "active-assurance-mcp"
    },
    "ems": {
        "tag": "ems-mcp"
    },
   "juniper-resiliency-interface": {
        "tag": "juniper-resiliency-interface-mcp"
   }
}
