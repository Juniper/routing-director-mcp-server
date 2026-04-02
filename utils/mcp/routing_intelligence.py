import utils.mcp.server as _server
from utils.lm_calls.tools.routing_intelligence.routing_intelligence import (
    get_jri_forwarding_exceptions,
    get_jri_os_exceptions,
    get_jri_routing_exceptions,
)

_server.mcp.tool(get_jri_forwarding_exceptions, tags={'juniper-resiliency-interface-mcp'})
_server.mcp.tool(get_jri_os_exceptions, tags={'juniper-resiliency-interface-mcp'})
_server.mcp.tool(get_jri_routing_exceptions, tags={'juniper-resiliency-interface-mcp'})
