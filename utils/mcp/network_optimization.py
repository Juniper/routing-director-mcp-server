from utils.mcp.server import mcp
from utils.lm_calls.tools.network_optimization.topology import (
    get_topology_list, get_links_in_topology, get_lsps_in_topology, get_nodes_in_topology, create_lsp
)

mcp.tool(get_topology_list, tags={'custom-default'})
mcp.tool(get_links_in_topology, tags={'custom-default'})
mcp.tool(get_lsps_in_topology, tags={'custom-default'})
mcp.tool(get_nodes_in_topology, tags={'custom-default'})
mcp.tool(create_lsp, tags={'custom-default'})