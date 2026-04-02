from utils.mcp.server import mcp
from utils.lm_calls.tools.ems.ems import (
    get_orgs, get_devices_sync, get_device_info, get_api_info, execute_api_call, get_config_templates,
    create_update_config_template, deploy_config_template_on_device, get_site_list, get_alerts_list, get_alerts_count,
    get_outbound_ssh_commands
)

mcp.tool(get_orgs, tags={'custom-default'})
mcp.tool(get_devices_sync, tags={'custom-default'})
mcp.tool(get_device_info, tags={'custom-default'})
# mcp.tool(get_api_info, tags={'custom-default'})
# mcp.tool(execute_api_call, tags={'custom-default'})
mcp.tool(get_config_templates, tags={'custom-default'})
mcp.tool(create_update_config_template, tags={'custom-default'})
mcp.tool(deploy_config_template_on_device, tags={'custom-default'})
mcp.tool(get_site_list, tags={'custom-default'})
mcp.tool(get_alerts_count, tags={'custom-default'})
mcp.tool(get_alerts_list, tags={'custom-default'})
mcp.tool(get_outbound_ssh_commands, tags={'custom-default'})

