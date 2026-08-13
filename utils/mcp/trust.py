from utils.mcp.server import mcp
from utils.lm_calls.tools.trust.trust import (
    get_trust_devices, list_compliance_scans, list_compliance_scan_benchmark_docs,
    create_compliance_scan, get_compliance_doc, get_compliance_scan_details,
    list_device_advisory_ids, get_advisory_details, get_vulnerability_statistics,
    correlate_sirt_with_active_config
)
from utils.lm_calls.tools.trust.security_report import generate_security_report


mcp.tool(get_trust_devices, tags={'custom-default'})
mcp.tool(list_compliance_scans, tags={'custom-default'})
mcp.tool(list_compliance_scan_benchmark_docs, tags={'custom-default'})
mcp.tool(create_compliance_scan, tags={'custom-default'})
mcp.tool(get_compliance_doc, tags={'custom-default'})
mcp.tool(get_compliance_scan_details, tags={'custom-default'})
mcp.tool(list_device_advisory_ids, tags={'custom-default'})
mcp.tool(get_advisory_details, tags={'custom-default'})
mcp.tool(get_vulnerability_statistics, tags={'custom-default'})
mcp.tool(correlate_sirt_with_active_config, tags={'custom-default'})
mcp.tool(generate_security_report, tags={'custom-default'})
