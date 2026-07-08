import sys
import re
import json
import requests

from utils.lm_calls.agent_directives import attach_directives, directives_response
from utils.lm_calls.paragon.constants import con, X_FROM, FH_ORDER_MGMT, USE_EXTERNAL_API, INSIGHTS_API_SERVER
from utils.lm_calls.tools.constants import uuid_regex
from utils.lm_calls.tools.helper import validate_org_id

import logging
logger = logging.getLogger(__name__)

vpn_types = {
    "l3vpn": "l3vpn",
    "l2vpn": "elan-evpn-csm",
    "elan-evpn-csm": "elan-evpn-csm",
    "l2circuit": "eline-l2circuit-nsm",
    "eline-l2circuit-nsm": "eline-l2circuit-nsm",
    "eline-evpn-vpws-csm": "eline-evpn-vpws-csm"
}


@validate_org_id
def get_customers(org_id:str) -> str:
    """
    Fetch all customers

    Args:
        org_id (str): The ID of the organization. This is a mandatory parameter.

    Returns:
        List of customers
    """
    try:
        if USE_EXTERNAL_API is False:
            resp = con.request(method="GET", url=f"{FH_ORDER_MGMT}apis/order/v1/orgs/{org_id}/customers")
        else:
            resp = con.request(method="GET", url=f"/service-orchestration/api/v1/orgs/{org_id}/order/customers")
        return json.dumps(resp.json())
    except Exception as exp:
        logger.error(f"Failed to get customers {exp}")
        return json.dumps({"error": str(exp)})

# Method to list vpns
# TODO: sites: List[str] filter is not supported by FH yet. Raised below ticket to support this.
#  Until then, parameter is removed from the function signature.
# https://paragon-automation.atlassian.net/browse/FH-6550
@validate_org_id
def list_available_vpns(
        org_id: str, customer_uuid: str, vpn_name: str, vpn_uuid: str, vpn_type: str, offset: int) -> str:
    """
    Returns a list of available VPNs(service instances).

    Key Features:
        - Filter VPNs using optional parameters

    Use this function when the user asks:
    - "What VPNs are available?"
    - "List VPNs"

    Args:
        org_id: ORD ID of the organization. This is a mandatory parameter.
        customer_uuid(optional): Default "". Filter by UUID of the customer (e.g., "f2199f26-60cc-4ebc-a73b-dd93a1920d3c"). Use get_customers to get customer UUID. Do not give customer name here.
        vpn_uuid: Filter by VPN UUID (e.g., "f2199f26-60cc-4ebc-a73b-dd93a1920d3c"). This is an optional parameter.
        vpn_name: Filter by VPN name. Use this only when you know VPN name. This is an optional parameter.
        vpn_type: Filter by type of VPN. This is an optional parameter.
        offset: Offset to start from. This is an optional parameter. Default is 0.
    Returns:
        str: JSON string containing available VPNs
    """
    per_page = 50
    endpoint = f"{FH_ORDER_MGMT}apis/order/v1/orgs/{org_id}/instances"
    if USE_EXTERNAL_API:
        endpoint = f"/service-orchestration/api/v1/orgs/{org_id}/order/instances"
    sites = []
    if not vpn_name and vpn_type:
        vpn_type = vpn_type.lower()
        if vpn_type not in vpn_types:
            return f"Given VPN type is not valid. VPN type should be one of {vpn_types.keys()}"
        vpn_type = vpn_types[vpn_type]

    try:
        # Make the GET request
        headers = {"X-FROM": X_FROM, "per-page": str(per_page), "current-offset": str(offset)}
        params = {
            "filter": ".[] | del(.place, .order_status.components, .order_status.workflow_trace, .l2vpn_svc?.sites.site[]?.site_network_accesses.site_network_access[]?.placement_interface, .l3vpn_svc?.placement_location_options, .l3vpn_svc?.sites.site[]?.site_network_accesses.site_network_access[]?.placement_interface, .l3vpn_svc?.sites.site[]?.site_network_accesses.site_network_access[]?.placement_options)"
        }
        if (not vpn_name) and vpn_type:
            headers["db-filter-parameters"] = f'(order.design_id=="{vpn_type}");'
        else:
            headers["db-filter-parameters"] = 'order.design_id=in=("l3vpn","elan-evpn-csm","eline-l2circuit-nsm","eline-evpn-vpws-csm");'
        if customer_uuid and re.match(uuid_regex, customer_uuid):
            headers["db-filter-parameters"] = (
                    headers.get("db-filter-parameters", "") + f'(order.customer_id=="{customer_uuid}");')
        elif customer_uuid:
            res = get_customers(org_id=org_id)
            customers = json.loads(res)
            for customer in customers:
                if customer["name"] == customer_uuid:
                    customer_uuid = customer["id"]
                    headers["db-filter-parameters"] = (
                            headers.get("db-filter-parameters", "") + f'(order.customer_id=="{customer_uuid}");')
                    break
        if vpn_uuid and re.match(uuid_regex, vpn_uuid):
            if USE_EXTERNAL_API:
                endpoint = f"/service-orchestration/api/v1/orgs/{org_id}/order/customers//instances/{vpn_uuid}"
            else:
                endpoint = f"{FH_ORDER_MGMT}apis/order/v1/orgs/{org_id}/customers//instances/{vpn_uuid}"
            params = {
                "filter": "del(.place, .order_status.components, .order_status.workflow_trace, .l2vpn_svc?.sites.site[]?.site_network_accesses.site_network_access[]?.placement_interface, .l3vpn_svc?.placement_location_options, .l3vpn_svc?.sites.site[]?.site_network_accesses.site_network_access[]?.placement_interface, .l3vpn_svc?.sites.site[]?.site_network_accesses.site_network_access[]?.placement_options)"
            }
        elif vpn_uuid and not vpn_name:
            vpn_name = vpn_uuid
        if vpn_name:
            headers["db-filter-parameters"] = (
                    headers.get("db-filter-parameters", "") + f'(order.instance_id=="{vpn_name}");')
        if sites:
            sites = '","'.join(sites)
            headers["db-filter-parameters"] = (
                    headers.get("db-filter-parameters", "") + f'(order.instance_id=in=("{sites}"));')
        if "db-filter-parameters" in headers:
            headers["db-filter-parameters"] = headers["db-filter-parameters"][:-1]

        response = con.request(method="GET", url=endpoint, headers=headers, params=params)
        # Return the JSON response
        total_count = response.headers.get("Grpc-Metadata-Total_size", None)
        resp = {"vpn_list": response.json()}

        # LLM seems to hallucinate between VPN UUID and VPN name as both of them are termed as id's in the data.
        # So, converting the instance_id to vpn_name and design_id to vpn_type
        for vpn in resp["vpn_list"]:
            if "instance_id" in vpn:
                vpn["vpn_name"] = vpn["instance_id"]
                del vpn["instance_id"]
            if "design_id" in vpn:
                vpn["vpn_type"] = vpn["design_id"]
        resp["filtered_count"] = len(resp["vpn_list"])
        if total_count:
            resp["total_vpns"] = total_count
        attach_directives(resp, f"""Follow below instructions:
        1) If this response has some VPN's, but does not have the VPN you are looking for, or does not have full list of VPN's, then call list_available_vpns with offset {offset + 1} to get the next set of VPNs.
        2) Give total VPNs from total_count in the summary
        3) If not mentioned by the user, display the VPN results in tabular format
        4) Make sure most of the basic information is displayed""")
        return json.dumps(resp)
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching metadata from {endpoint}: {e}")
        return json.dumps({"error" : str(e)})

def get_vpn_health() -> str:
    """
    Get instructions to fetch VPN health or details.
    Returns: String containing vpn metrics instructions
    """
    h = """
    Follow below instructions to get VPN health or details
    1) Use list_available_vpns to get the basic information about the VPN
    2) From step1 get information given vpn like service_type(design_id)
    3) Using service_type from step 2, call  get_vpn_metrics of insight_agent get detailed vpn health
    4) Revolve device mac addresses to device names using get_device_list from papi_agent
    Above steps needs to be executed to get VPN health.
    """
    return directives_response(h)


@validate_org_id
def get_vpn_metrics(org_id: str, vpn_uuid: str) -> str:
    """
    Fetch VPN metrics or details.
    Args:
        org_id (str, required): Organization ID.
        vpn_uuid (str, optional): Filter by VPN UUID (e.g., "f2199f26-60cc-4ebc-a73b-dd93a1920d3c").
    Returns:
        List of metrics
    """
    logger.info("Inside get_vpn_metrics")
    type_to_domain = {
        "l3vpn": ["l3vpn", "physical_interfaces", "logical_interfaces", "bgp", "ospf"],
        "l2vpn": ["l2vpn", "physical_interfaces", "logical_interfaces", "oam", "lldp"],
        "elan-evpn-csm": ["elan-evpn-csm", "physical_interfaces", "logical_interfaces", "oam", "lldp"],
        "eline-evpn-vpws-csm": ["eline-evpn-vpws-csm", "physical_interfaces", "logical_interfaces", "oam", "lldp"],
        "eline-l2circuit-nsm": ["eline-l2circuit-nsm", "physical_interfaces", "logical_interfaces"]
    }
    vpn_details = {}

    res = None
    if vpn_uuid and not re.match(uuid_regex, vpn_uuid):
        res = list_available_vpns(org_id=org_id, customer_uuid="", vpn_name=vpn_uuid, vpn_uuid="", vpn_type="", offset=0)
    elif vpn_uuid:
        res = list_available_vpns(org_id=org_id, customer_uuid="", vpn_name="", vpn_uuid=vpn_uuid, vpn_type="", offset=0)
    if not res:
        return json.dumps({"error": "VPN not found"})
    vpn_resp = json.loads(res)
    vpn_resp = vpn_resp.get("vpn_list", [])
    if not vpn_resp:
        return json.dumps({"error": "VPN not found"})
    for vpn in vpn_resp:
        if vpn["instance_uuid"] == vpn_uuid:
            vpn_details = vpn
            vpn_type = vpn_details.get("design_id", "")
            vpn_details = vpn
            break
    if not vpn_details:
        return json.dumps({"error": "VPN not found"})

    url = f'{INSIGHTS_API_SERVER}api/v2/orgs/{org_id}/service_instances/{vpn_uuid}/metrics'
    final_response = {
        "response": {},
    }
    for domain in type_to_domain.get(vpn_type, []):
        params = {
            "service_type": vpn_type,
            "type": domain
        }
        try:
            resp = con.request(method="GET", url=url, headers={"X-FROM": X_FROM},params=params)
        except requests.exceptions.RequestException as exp:
            logger.error(f"Failed to get VPN metrics {exp}", file=sys.stderr)
        else:
            res = resp.json()
            service_keys = list(res.get("service_instance", {}).keys())
            if service_keys:
                final_response[domain] = res.get("service_instance")[service_keys[0]]
    logger.debug(final_response)
    attach_directives(final_response, "While providing answer to the user, resolve all the 'device_id' to device names using get_device_list tool from papi_agent")
    return json.dumps(final_response)