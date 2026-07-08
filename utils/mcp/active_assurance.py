from utils.mcp.server import mcp
from utils.lm_calls.tools.active_assurance.active_assurance import (active_assurance_list_test_agents_sync,
                                                                    active_assurance_list_monitors_sync,
                                                                    active_assurance_list_tests_sync,
                                                                    active_assurance_list_plugin_schema_sync,
                                                                    active_assurance_list_measurements_with_metrics_sync,
                                                                    active_assurance_get_current_time_sync)


mcp.tool(active_assurance_list_test_agents_sync, tags={'custom-default'})
mcp.tool(active_assurance_list_monitors_sync, tags={'custom-default'})
mcp.tool(active_assurance_list_tests_sync, tags={'custom-default'})
mcp.tool(active_assurance_list_plugin_schema_sync, tags={'custom-default'})
mcp.tool(active_assurance_list_measurements_with_metrics_sync, tags={'custom-default'})
mcp.tool(active_assurance_get_current_time_sync, tags={'custom-default'})

