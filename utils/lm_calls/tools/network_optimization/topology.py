import os
import json
import logging

from utils.lm_calls.paragon.constants import (PAPI_URL, con, USE_EXTERNAL_API)
from utils.lm_calls.tools.ems.config_template import ConfigTemplate

logger = logging.getLogger(__name__)

def get_topology_list(org_id: str) -> str:
    """
    Retrieves the list of topologies from the Routing Director
    :param org_id: The organization ID
    :return: JSON string containing the list of topologies
    """
    if USE_EXTERNAL_API is False:
        return "This function is not supported for internal API"
    resp = con.request(method="GET", url=f"/topology/api/v1/orgs/{org_id}")
    return json.dumps(resp.json(), indent=2)

def get_nodes_in_topology(org_id: str, topology_id: str, page: int =1, per_page: int =1) -> str:
    """
    Retrieves nodes in a topology
    :param org_id: The organization ID
    :param topology_id: The topology id
    :param page: The page number to retrieve, default to 1 if not specified
    :param per_page: The number of items per page, default to 1000 if not specified, maximum is 1000 if set to a value greater than 1000
    :return: JSON string containing the list of nodes of a topology
    """
    if USE_EXTERNAL_API is False:
        return "This function is not supported for internal API"
    params = {
        page: page,
        per_page: per_page

    }
    resp = con.request(method="GET", url=f"/topology/api/v1/orgs/{org_id}/{topology_id}/nodes", params=params)
    return json.dumps(resp.json(), indent=2)

def get_links_in_topology(org_id: str, topology_id: str, page: int =1, per_page: int =1) -> str:
    """
    Retrieves links in a topology
    :param org_id: The organization ID
    :param topology_id: The topology id
    :param page: The page number to retrieve, default to 1 if not specified
    :param per_page: The number of items per page, default to 1000 if not specified, maximum is 1000 if set to a value greater than 1000
    :return: JSON string containing the list of links of a topology
    """
    if USE_EXTERNAL_API is False:
        return "This function is not supported for internal API"
    params = {
        page: page,
        per_page: per_page

    }
    resp = con.request(method="GET", url=f"/topology/api/v1/orgs/{org_id}/{topology_id}/links", params=params)
    return json.dumps(resp.json(), indent=2)

def get_lsps_in_topology(org_id: str, topology_id: str, page: int =1, per_page: int =1) -> str:
    """
    Retrieves LSP's in a topology.
    :param org_id: The organization ID
    :param topology_id: The topology id
    :param page: The page number to retrieve, default to 1 if not specified
    :param per_page: The number of items per page, default to 1000 if not specified, maximum is 1000 if set to a value greater than 1000
    :return: JSON string containing the LSPs of links of a topology
    """
    if USE_EXTERNAL_API is False:
        return "This function is not supported for internal API"
    params = {
        page: page,
        per_page: per_page

    }
    resp = con.request(method="GET", url=f"/topology/api/v1/orgs/{org_id}/{topology_id}/te-lsps", params=params)
    return json.dumps(resp.json(), indent=2)

# NOTE: Not good tool. Only for demos
def create_lsp(org_id: str, topology_id: str, payload: dict) -> str:
    """
    Creates LSPs between 2 nodes.
    From and To addresses should be node loopback IPs. Get the info from get_nodes_in_topology
    :param org_id: The organization ID
    :param topology_id:The topology id
    :param payload: payload should contain endpoints of the LSP and LSP attributes. Eg: {"name":"test-ai","creationConfigurationMethod":"PCEP","pathType":"primary","provisioningType":"SR","from":{"address":"100.0.0.4","topoObjectType":"ipv4"},"to":{"address":"100.0.0.5","topoObjectType":"ipv4"},"plannedProperties":{"bandwidth":"0","holdingPriority":7,"setupPriority":7,"design":{"adminGroups":{},"routingMethod":"default"},"policy":{"bandwidthSizing":{"enabled":false}}}}'
    :return:
    """
    if USE_EXTERNAL_API is False:
        return "This function is not supported for internal API"
    headers = {
        "Content-Type": "application/json",
    }
    resp = con.request(method="POST", url=f"/topology/api/v1/orgs/{org_id}/{topology_id}/te-lsps", headers=headers, json=payload)
    return json.dumps(resp.json(), indent=2)