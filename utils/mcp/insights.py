from utils.mcp.server import mcp
from utils.lm_calls.tools.observability.custom_kpis import (
    get_custom_kpi_instantiations, get_observability_kpis, get_observability_kpi_data
)

mcp.tool(get_custom_kpi_instantiations, tags={'custom-default'})
mcp.tool(get_observability_kpis, tags={'custom-default'})
mcp.tool(get_observability_kpi_data, tags={'custom-default'})
