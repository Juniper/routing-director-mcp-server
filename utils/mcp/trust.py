from utils.mcp.server import mcp
from utils.lm_calls.tools.trust.trust import (
    get_trust_devices, list_compliance_scans, list_compliance_scan_benchmark_docs, create_compliance_scan, get_compliance_doc, get_compliance_scan_details
)

mcp.tool(get_trust_devices, tags={'custom-default'})
mcp.tool(list_compliance_scans, tags={'custom-default'})
mcp.tool(list_compliance_scan_benchmark_docs, tags={'custom-default'})
mcp.tool(create_compliance_scan, tags={'custom-default'})
mcp.tool(get_compliance_doc, tags={'custom-default'})
mcp.tool(get_compliance_scan_details, tags={'custom-default'})