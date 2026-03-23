from utils.mcp.server import mcp
from utils.lm_calls.tools.fh import get_customers, list_available_vpns, get_vpn_metrics

mcp.tool(get_customers, tags={'custom-default'})
mcp.tool(list_available_vpns, tags={'custom-default'})
mcp.tool(get_vpn_metrics, tags={'custom-default'})