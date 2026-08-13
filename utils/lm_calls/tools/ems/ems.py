import json
import logging
import os
import re
import sys
import urllib.parse
from typing import List

import httpx
import requests

from utils.lm_calls.agent_directives import attach_directives
from utils.lm_calls.paragon.constants import (PAPI_URL, con, USE_EXTERNAL_API, ALERTMANAGER_URL, X_FROM,
                                              BLACKLIST_REQUEST_JUNOS_COMMANDS_REGEX, OCTALK_RPC,
                                              BLOCKED_JUNOS_RPC_TAGS, ALERT_SEVERITIES)
from utils.lm_calls.tools.constants import uuid_regex
from utils.lm_calls.tools.ems.config_template import ConfigTemplate
from utils.lm_calls.tools.fh import list_available_vpns
from utils.lm_calls.tools.helper import validate_device_uuid, validate_org_id

# Regex to find Junos pipe commands (match, except, find) with unquoted patterns containing |
_junos_pipe_pattern_regex = re.compile(
    r'(\|\s*(?:match|except|find)\s+)(?!")((?:[^|"\s]+\|)+[^|"\s]+)(?!")',
)

# Regex to detect any blocked RPC tag, e.g. <load-configuration ...> or <edit-config>.
_junos_blocked_rpc_regex = re.compile(
    r"<\s*/?\s*(?:" + "|".join(re.escape(tag) for tag in BLOCKED_JUNOS_RPC_TAGS) + r")\b",
    re.IGNORECASE,
)


def _is_xml_command(command: str) -> bool:
    """
    Return True if the command contains a blocked Junos RPC payload (see
    ``BLOCKED_JUNOS_RPC_TAGS``), which must not be run through operational command tools.
    """
    return bool(_junos_blocked_rpc_regex.search(command or ""))


def _quote_junos_pipe_patterns(command: str) -> str:
    """
    Auto-quote unquoted regex patterns in Junos pipe commands that contain | characters.
    e.g. '| match up|down' → '| match "up|down"'
    This prevents the | from being interpreted as an additional Junos pipe operator.
    """
    return _junos_pipe_pattern_regex.sub(r'\1"\2"', command)


log_level = os.getenv("LOG_LEVEL", "ERROR").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.ERROR))
logger = logging.getLogger(__name__)

tools_dir = os.path.dirname(os.path.dirname(__file__))
assets_dir = os.path.join(tools_dir, "assets")
ems_openapi_file = os.path.join(assets_dir, "ems_openapi.json")
all_apis_file = os.path.join(assets_dir, "all_apis.json")


@validate_org_id
def get_site_id(org_id: str, site_name: str) -> str:
    try:
        if USE_EXTERNAL_API is False:
            url = f'{PAPI_URL}internal/orgs/{org_id}/sites'
            res = con.request(method="GET", url=url, headers={"X-FROM": X_FROM})
        else:
            res = con.request(method="GET", url=f"/api/v1/orgs/{org_id}/sites")
    except (requests.exceptions.RequestException, httpx.HTTPError) as exp:
        err_msg = 'Failed to get site details'
        print(f"{err_msg}: {exp}", file=sys.stderr)
        return err_msg
    else:
        details = res.json()
        for site in details:
            if site.get("name") == site_name:
                return site.get("id")
    return "Failed to get site details"


@validate_org_id
def resolve_site_id(org_id: str, site_id: str) -> tuple[str, str]:
    """Resolve a site identifier to a site UUID.

    Accepts either a site UUID (returned as-is) or a site name (resolved to
    its UUID via get_site_id). Centralizes the resolution + validation logic
    so all callers behave consistently.

    Returns:
        tuple[str, str]: (resolved_site_id, error_message). On success the
        error_message is an empty string; on failure resolved_site_id is an
        empty string and error_message contains a user-facing message.
    """
    if re.match(uuid_regex, site_id):
        return site_id, ""
    resolved = get_site_id(org_id=org_id, site_name=site_id)
    if resolved == "Failed to get site details":
        return "", f"No site found matching the name '{site_id}'. Please verify the site name and try again."
    return resolved, ""


@validate_org_id
def get_outbound_ssh_commands(org_id: str, site_id: str = "") -> str:
    """
    Retrieves outbound SSH commands for devices. Can be filtered by site or get commands for all devices in the org.
    This function is used to onboard and connect the device to Routing Director.

    :param org_id: The organization ID (UUID format). This is a mandatory parameter.
    :param site_id: The site ID (UUID format). Optional parameter. If provided, returns SSH commands for devices at that specific site.
                    If site name is provided, use get_site_id to convert it to UUID first.
    :return: JSON string containing the outbound SSH commands
    """
    logger.info(f"get_outbound_ssh_commands - org_id: {org_id}, site_id: {site_id}")

    # Validate site_id is a UUID if provided, if not try to resolve it
    if site_id and not re.match(uuid_regex, site_id):
        return "Invalid site_id format. Please provide a valid UUID or use get_site_id to resolve site name to UUID."


    # Only add site_id to params if it's provided
    params = None
    if site_id:
        params = {
            "site_id": site_id
        }

    try:
        if USE_EXTERNAL_API is False:
            url = f'{PAPI_URL}internal/orgs/{org_id}/ocdevices/outbound_ssh_cmd'
            res = con.request(method="GET", url=url, headers={"X-FROM": X_FROM}, params=params)
        else:
            res = con.request(method="GET", url=f'/api/v1/orgs/{org_id}/ocdevices/outbound_ssh_cmd', params=params)
    except requests.exceptions.RequestException as exp:
        error_msg = f"Failed to get outbound SSH commands for org {org_id}" + (f" and site {site_id}" if site_id else "") + f": {exp}"
        print(error_msg, file=sys.stderr)
        return error_msg
    else:
        return json.dumps(res.json(), indent=2)


def get_orgs() -> str:
    """
    Retrieves the list of organizations from the Routing Director
    :return: JSON string containing the list of organizations
    """
    if USE_EXTERNAL_API is False:
        return "Not implemented"
    else:
        resp = con.request(method="GET", url="/api/v1/self")
        resp = resp.json()
        if con.org_id != "":
            for privilege in resp.get('privileges', []):
                if privilege.get("org_id", "") == con.org_id:
                    return json.dumps(privilege, indent=2)
            return json.dumps(resp, indent=2)


@validate_org_id
def get_site_list(org_id:str, name: str = "", limit: int = 50) -> dict|str :
    """
    Use this function to retrieve information about up to 50 sites in Routing Director
    Automation, with or without filters.

    Key Features:
        - Filter sites using optional parameters

    :param org_id: ORG ID of the organization. This is a mandatory parameter.
    :param name: Filter by site name (e.g., "mySiteInCA"),Optional parameter. If value not present/available assign default value as "" (empty string)
    :param limit: Maximum number of sites to return (default 50), set to 0 to return all sites.

    Returns:
       If the response contains any empty fields, it means the API is returning default values. In such cases, respond with: "No sites found matching the given search criteria." Otherwise, list the sites retrieved based on the provided query.
    """
    # logger.debug("Getting list of sites")
    params = {}
    if name and len(name.strip()) > 0:
        params['name'] = name

    encoded_params = urllib.parse.urlencode(params)

    try:
        if USE_EXTERNAL_API is False:
            url = f'{PAPI_URL}internal/orgs/{org_id}/sites?{encoded_params}'
            res = con.request(method="GET", url=url, headers={"X-FROM": X_FROM})
        else:
            res = con.request(url=f"/api/v1/orgs/{org_id}/sites", method="GET")

    except requests.exceptions.RequestException as exp:
        print(f"Failed to get site details {exp}", file=sys.stderr)
        return "Failed to get site details"
    else:
        details = res.json()

    sites = [
        {"name": site.get("name", ""), "address": site.get("address", ""), "country_code": site.get("country_code", ""),
         "latlng": site.get("latlng", {}), "id": site.get("id", "")}
        for site in details
    ]
    num_sites = len(sites)
    sites_to_display = limit if limit > 0 else num_sites
    if num_sites > sites_to_display:
        sites = sites[:sites_to_display]
        comment = (f"There are a total of {num_sites} sites available. Displaying the top 50 results. "
                   f"For more specific results, please search by site name.")
    else:
        comment = f"There are a total of {num_sites} sites available. Displaying all the results."
    final_result = { "result": sites, "comment": comment }

    return final_result


@validate_org_id
def get_devices_sync(org_id: str, vendor: str="", host: str="", model:str="", site_id:str="", device_uuid:str="",  limit:int = 50, offset:int = 0) -> str:
    """
    Retrieves the list of devices from the Routing Director. You can also fetch the device details like alert, device_uuid, connected/disconnected, device model type.
    Filter devices using one or a combination of optional parameters.
    Return only 50 devices unless the user specifically requests for more device details.

    :param org_id: The organization ID. compulsory parameter.
    :param vendor: Filter by device vendor, possible values are "Juniper Networks", "Cisco", "Nokia". Optional Parameter.
    :param host: DNS host name or IP of the device. Optional parameter.
    :param model: Filter by device model (e.g., "MX960"). Optional parameter.
    :param site_id: Filter by site ID (e.g., "f2199f26-60cc-4ebc-a73b-dd93a1920d3c"). Optional parameter.
    :param limit: Maximum number of devices to return. Optional parameter, defaults to 50, do not change this value unless the user specifically requests for more device details.
    :param offset: Number of devices to skip before starting to return results, used for pagination. Optional parameter, defaults to 0. For example, to fetch the second page of 50 devices, set offset to 50.
    :param device_uuid: Filter by device UUID (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"). Optional parameter.
    :return: JSON string containing the list of devices
    """
    params = {
        "limit": limit,
        "offset": offset,
    }
    if model:
        params["model"] = model + "*"
    if device_uuid:
        params["id"] = device_uuid
    if vendor:
        params['vendor'] = vendor + "*"
    if site_id:
        params['site_id'] = site_id
    if host:
        params['hostname'] = host

    try:
        if USE_EXTERNAL_API is False:
            resp = con.request(url=f"{PAPI_URL}internal/orgs/{org_id}/device/profiles/search", params=params, method="GET")
        else:
            resp = con.request(url=f"/api/v1/orgs/{org_id}/device/profiles/search", params=params, method="GET")
    except requests.exceptions.RequestException as exp:
        print(f"Failed to get device details {exp}", file=sys.stderr)
        return "Failed to get device details"
    else:
        details = resp.json()

    devices = []
    for dev in details.get("results", []):
        device = {
            "name": dev.get("name", ""),
            "device_uuid": dev.get("uuid") or dev.get("id") or "",
            "model": dev.get("model", ""),
            "alerts": {"critical": dev.get("alert_counts_critical", 0), "major": dev.get("alert_counts_major", 0), "minor": dev.get("alert_counts_minor", 0)},
            "connected": dev.get("connected", False)
        }

        devices.append(device)
    num_devices = details.get("total", 0)
    if num_devices > limit:
        comment = (f"There are a total of {num_devices} devices available. Displaying the {limit} results. "
                   f"For more specific results, please search by model name, vendor, site ID, device_uuid, host.")
    else:
        comment = f"There are a total of {num_devices} devices available. Displaying all the results."
    res = {
        "total_devices": details.get("total", 0),
        "devices": devices,
        "comment": comment,
    }
    attach_directives(res, """
    Do not send only the device UUID in the response.
    Include the device’s IP address or hostname as well for proper identification.
    """)
    devices_str = json.dumps(res)

    return devices_str


@validate_org_id
def get_device_info(org_id: str, device_id: str) -> str:
    """
    Retrieves the device information from the Routing Director
    :param org_id: The organization ID
    :param device_id: The device ID. This is UUID of the device
    :return: JSON string containing the device information
    """
    logger.info("get_device_info")
    params = {
        "id": device_id
    }

    try:
        if USE_EXTERNAL_API is False:
            resp = con.request(method="GET", url=f"{PAPI_URL}internal/orgs/{org_id}/device/profiles/search", params=params)
        else:
            resp = con.request(method="GET", url=f"/api/v1/orgs/{org_id}/device/profiles/search", params=params)
    except requests.exceptions.RequestException as exp:
        print(f"Failed to get device details {exp}", file=sys.stderr)
        return "Failed to get device details"

    return json.dumps(resp.json(), indent=2)


def get_api_info() -> str:
    """
    Retrieves the API information from the Routing Director
    :return: JSON string containing the API information
    """
    logger.info("get_api_info")
    with open(ems_openapi_file) as fh:
    #with open(all_apis_file) as fh:
        resp = json.load(fh)
    return json.dumps(resp, indent=2)


def execute_api_call(api_path: str, method: str, body: str, headers: dict) -> str:
    """
    Executes the API call on the Routing Director
    :param api_path: The API path
    :param method: The HTTP method
    :param body: The request body
    :param headers: The request headers
    :return: JSON string containing the response
    """
    logger.info("execute_api_call")
    if USE_EXTERNAL_API is False:
        return "Not Implemented"
    if body:
        body = json.loads(body)
    logger.error(f"method={method}, endpoint={api_path}, data={body}, headers={headers}")
    resp = con.request(method=method, url=api_path, data=body, headers=headers)
    return json.dumps(resp, indent=2)


def get_sample_config_template() -> str:
    """
    Retrieves the sample config template from the Routing Director which can be used as reference to create a new
    config templates
    :return: String containing the sample config template
    """
    logger.info("get_sample_config_template")
    resp = con.request(method="GET", url="/static/config_templates_sample_Juniper.txt")
    return resp


@validate_org_id
def get_config_templates(org_id: str, template_id: str ="", template_name: str ="") -> str:
    """
    Retrieves all configuration templates for a given organization
    :param org_id: The organization ID
    :param template_id: The template ID. This is UUID of the template
    :param template_name: The template name
    :return: JSON string containing the list of config templates
    """
    logger.info("get_config_templates")
    if USE_EXTERNAL_API is False:
        return "Not Implemented"
    url = f"/api/v1/configtemplates/{org_id}"
    if template_id:
        url = f"{url}/{template_id}"

    resp = con.request(method="GET", url=url)
    resp = resp.json()
    if template_id != "":
        return json.dumps(resp, indent=2)

    if template_name != "" and isinstance(resp, list):
        for template in resp:
            if template.get("name", "") == template_name:
                return json.dumps(template, indent=2)
        return json.dumps([], indent=2)
    return json.dumps(resp.json(), indent=2)


@validate_org_id
def create_update_config_template(org_id: str, template: ConfigTemplate, template_id: str="", template_name: str="") -> str:
    """
    Creates or updates a configuration template
    :param org_id: The organization ID
    :param template_id: The template ID. This is UUID of the template
    :param template_name: The template name
    :param template: The template content in JSON format.
    :return: JSON string containing the response
    """
    logger.info("create_update_config_template")

    # Convert Pydantic model to dict, excluding None values
    template_dict = template.model_dump(exclude_none=True)
    template_dict["view_def"] = '{"viewdef":{"version":"2.0","path":"$","viewdefs":[{"id":"entry","type":"panel","path":"configuration","properties":{"size":"xlarge"},"readonly":false,"children":[{"path":".","children":[],"fullPath":"configuration","dataFullPath":"configuration"}],"fullPath":"configuration","dataFullPath":"configuration","uniqueId":"entry_0"}],"resources":[]}}'
    if USE_EXTERNAL_API is False:
        return "Not Implemented"
    headers = {
        "Content-Type": "application/json",
    }
    existing_template = get_config_templates(org_id=org_id, template_id=template_id, template_name=template_name)
    logger.info(f"existing_template: {existing_template}")
    if not json.loads(existing_template):
        resp = con.request(method="POST", url=f"/api/v1/configtemplates/{org_id}", headers=headers, json=template_dict)
    else:
        resp = con.request(method="PUT", url=f"/api/v1/configtemplates/{org_id}/{template_id}", headers=headers, json=template_dict)
    resp.raise_for_status()
    return json.dumps(resp.json(), indent=2)


@validate_org_id
def deploy_config_template_on_device(org_id: str, device_id: str, template_id: str, variables: dict) -> str:
    """
    Deploys a configuration template on a device
    :param org_id: The organization ID
    :param device_id: The device ID. This is UUID of the device
    :param template_id: The config template ID. This is UUID of the template
    :params variables: The variables to be used in the template
    :return: JSON string containing the response
    """
    logger.info("deploy_config_template_on_device")
    if USE_EXTERNAL_API is False:
        return "Not Implemented"
    headers = {
        "Content-Type": "application/json",
    }
    body = {
        "device_id": device_id,
        "payload": variables,
    }
    resp = con.request(method="POST", url=f"/api/v1/configtemplates/{org_id}/{template_id}/execute", headers=headers, json=body)
    resp.raise_for_status()
    return json.dumps(resp.json(), indent=2)


@validate_org_id
def get_alerts_count(org_id: str, *, device_uuid: str="", site_id: str="", alert_type: str="", severity: str="SEVERITY_MINOR",
                     include_acknowledged: bool=False, vpn_uuid: str = "", extra_params: dict = {}, return_data: bool = False) -> str:
    """
    Use this function to get the count of available active alerts for all devices or a specific device of the org. It also provides the count of alerts per severity value.

    Args:
        org_id(str): ORG ID of the organization.
        device_uuid(str): Device UUID (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"). Use get_devices_sync to retrieve it.
        site_id(str): Filter by site ID (e.g., "f2199f26-60cc-4ebc-a73b-dd93a1920d3c")
        alert_type(str): Filter by alert type (e.g., "routing.isis", "routing", "hardware.fpc.pfe.pfe-bad-route-discard", "hardware", "trust.vulnerability.advisory")
        severity(str): Minimum Alert severity filter. Alerts with the specified severity or higher will be included in the result. .Possible values are: "SEVERITY_CRITICAL","SEVERITY_MAJOR", "SEVERITY_MINOR", "SEVERITY_WARNING", "SEVERITY_INFO".
        include_acknowledged(bool): Default value is False. Includes acknowledged alerts in the response.
        vpn_uuid(str): Filter by VPN UUID only. Must be the actual UUID/instance_uuid in format like "f2199f26-60cc-4ebc-a73b-dd93a1920d3c". Do NOT use VPN name - only use the UUID identifier.
        extra_params(dict): Additional parameters to include in the API request.
        return_data(bool): If True, returns the raw alert data instead of a formatted string.

    Returns:
        str: Count of alerts and alerts per severity value.
    """
    severity = severity if severity in ALERT_SEVERITIES else "SEVERITY_MINOR"

    params = {
        "group_by_severity": "true",
        "severity": severity
    }

    if site_id:
        resolved_site_id, error = resolve_site_id(org_id=org_id, site_id=site_id)
        if error:
            return error
        params["subject.site_id"] = resolved_site_id
    if alert_type:
        params["type"] = alert_type
    if include_acknowledged:
        params["include_acked"] = "true"
    if device_uuid:
        params["subject.device_id"] = device_uuid
    if vpn_uuid:
        params["subject.service_id"] = vpn_uuid
    # Set extra parameters if any
    for k,v in extra_params.items():
        params[k] = v

    try:
        if USE_EXTERNAL_API is False:
            url = f"{ALERTMANAGER_URL}/alert-manager/api/v1/orgs/{org_id}/alerts/count"
            res = con.request(method="GET", url=url, headers={"X-FROM": X_FROM}, params=params)
        else:
            res = con.request(url=f"/alert-manager/api/v1/orgs/{org_id}/alerts/count", method="GET", params=params)
    except (requests.exceptions.RequestException, httpx.HTTPError) as exp:
        error_msg = f"Failed to get alert details for the organization {org_id}: {exp}"
        print(f"{error_msg}. error:exp", file=sys.stderr)
        return error_msg
    else:
        alerts_data = res.json().get("groups", [])

    if return_data:
        return json.dumps(alerts_data)

    if not alerts_data:
        return "No alerts found for the organization"

    comment = f"There are a total of {alerts_data[0].get('count', 0)} alerts available. Displaying the count of alerts per severity value:\nInfo:{alerts_data[0]['severity'].get('info', 0)}\nWarning:{alerts_data[0]['severity'].get('warning', 0)}\nMinor:{alerts_data[0]['severity'].get('minor', 0)}\nMajor:{alerts_data[0]['severity'].get('major', 0)}\nCritical:{alerts_data[0]['severity'].get('critical', 0)}"
    return comment


@validate_org_id
def get_alerts_for_device(org_id: str, device_uuid: str) -> str:
    """
    Retrieves the alerts for a device , irrespective of site severity and category.
    Use this function to get the alerts for a device.
    The alerts are grouped by category and severity.
    :param org_id: The organization ID
    :param device_uuid: The device UUID (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479")
    :return: JSON string containing the alerts grouped by category with severity counts
    """
    if USE_EXTERNAL_API is True:
        return "Not Implemented"

    # Call the alert-manager API with device_id as query parameter
    url = f"{ALERTMANAGER_URL}/alert-manager/api/v1/orgs/{org_id}/alerts"
    params = {
        "subject[device_id]": device_uuid
    }

    try:
        # First call to get the total count
        resp = con.request(method="GET", url=url, params=params)
        data = resp.json()

        total_count = data.get("total", 0)
        limit = data.get("limit", 50)

        # If total count is greater than default limit (50), fetch all records
        if total_count > limit:
            params["limit"] = total_count
            url_with_limit = f"{url}?limit={total_count}"
            resp = con.request(method="GET", url=url_with_limit, params=params)
            data = resp.json()

    except requests.exceptions.RequestException as e:
        return json.dumps({"error": str(e)}, indent=2)

    # Transform the response
    events = data.get("results", [])

    # Group alerts by accordion_classification_type and count severities
    alert_categories = {}

    for event in events:
        category = event.get("subject", {}).get("accordion_classification_type", "unknown")
        severity = event.get("severity", "")

        if category not in alert_categories:
            alert_categories[category] = {
                "critical": 0,
                "minor": 0
            }

        if severity == "SEVERITY_CRITICAL":
            alert_categories[category]["critical"] += 1
        elif severity == "SEVERITY_MINOR":
            alert_categories[category]["minor"] += 1

    # Build the output structure
    output = {
        "device_id": device_uuid,
        "org_id": org_id,
        "alert_category": [
            {
                category: {
                    "critical": counts["critical"],
                    "minor": counts["minor"]
                }
            }
            for category, counts in alert_categories.items()
        ]
    }

    return json.dumps(output, indent=2)


@validate_org_id
def get_alerts_list(org_id: str, *, device_uuid: str="", site_id: str="", vpn_uuid: str="", alert_type: str="", severity: str="SEVERITY_MAJOR", include_acknowledged: bool=False, extra_params: dict = {}) -> str:
    """
    Use this function if list of available active alerts for the org or a single device is required. Up to 50 alerts will be returned.
    Don't call this function if the count of alerts is required. Use get_alerts_count instead.
    Return the list of alerts do not summarize the alerts unless asked by user.

    IMPORTANT: Always use UUIDs for vpn_uuid and device_uuid parameters, never use names or MAC addresses.

    Args:
        org_id(str): ORG ID of the organization.
        device_uuid(str): Device UUID (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"). Use get_devices_sync to retrieve it.
        site_id(str): Filter by site ID, if you have site (e.g., "f2199f26-60cc-4ebc-a73b-dd93a1920d3c")
        vpn_uuid(str): Filter by VPN UUID only. Must be the actual UUID/instance_uuid in format like "f2199f26-60cc-4ebc-a73b-dd93a1920d3c". Do NOT use VPN name - only use the UUID identifier.
        alert_type(str): Filter by alert type (e.g., "routing.isis", "routing", "hardware.fpc.pfe.pfe-bad-route-discard", "hardware", "trust.vulnerability.advisory"). Use this only if you know full alert type or a prefix of alert type. For example, if you want to filter all hardware related alerts, use "hardware" as the alert_type value. If you want to filter only pfe alerts, use "hardware.fpc.pfe" as the alert_type value.
        severity(str): Minimum Alert severity filter. Alerts with the specified severity or higher will be included in the result. .Possible values are: "SEVERITY_CRITICAL","SEVERITY_MAJOR", "SEVERITY_MINOR", "SEVERITY_WARNING", "SEVERITY_INFO". Default is "SEVERITY_MAJOR"
        include_acknowledged(bool): Include acknowledged alerts in the response. Default is false
        extra_params(dict): Additional parameters to include in the API request.

    Returns(str): The list of alerts
    """

    if severity not in ["SEVERITY_CRITICAL", "SEVERITY_MAJOR", "SEVERITY_MINOR", "SEVERITY_WARNING", "SEVERITY_INFO"]:
        severity = "SEVERITY_MAJOR"

    params = {
        "severity": severity,
        "limit": 50
    }

    if site_id:
        resolved_site_id, error = resolve_site_id(org_id=org_id, site_id=site_id)
        if error:
            return error
        params["subject[site_id]"] = resolved_site_id
    if vpn_uuid:
        if vpn_uuid and re.match(uuid_regex, vpn_uuid):
            params["subject[service_id]"] = vpn_uuid
        else:
            vpns = list_available_vpns(
                org_id=org_id, customer_uuid="", vpn_name=vpn_uuid, vpn_uuid="", vpn_type="", offset=0)
            vpns = json.loads(vpns).get("vpn_list", [])
            if vpns:
                params["subject[service_id]"] = vpns[0].get("instance_uuid")
            else:
                return f"No VPNs found for the given name {vpn_uuid}"

    if alert_type:
        params["type"] = alert_type
    if include_acknowledged:
        params["include_acked"] = "true"
    if device_uuid:
        params["subject[device_id]"] = device_uuid

    # Set extra parameters if any
    for k,v in extra_params.items():
        params[k] = v

    try:
        if USE_EXTERNAL_API is False:
            url = f"{ALERTMANAGER_URL}/alert-manager/api/v1/orgs/{org_id}/alerts"
            res = con.request(method="GET", url=url, headers={"X-FROM": X_FROM}, params=params)
        else:
            res = con.request(url=f"/alert-manager/api/v1/orgs/{org_id}/alerts", method="GET", params=params)
    except (requests.exceptions.RequestException, httpx.HTTPError) as exp:
        error_msg = f"Failed to get alert details for the organization {org_id}: {exp}"
        return json.dumps({"error": error_msg})
    else:
        res = res.json()

    if not res:
        return "No alerts found"

    attach_directives(res, "Resolve all the device_id to device names in alerts using get_device_list tool from papi_agent")

    return json.dumps(res)


@validate_org_id
def get_site_alert_counts(org_id: str) -> List[dict]:
    """
    Retrieves alerts grouped by site ID with severity counts.
    Returns list of alert groups for sites with critical or major alerts.

    API: GET /alert-manager/api/v1/orgs/{org_id}/alerts/count?group_by=subject.site_id&group_by_severity=true&group_limit=50&severities=SEVERITY_CRITICAL,SEVERITY_MINOR

    Response structure:
    {
        "groups": [
            {
                "name": "27f9ee56-37ea-4f8e-95ca-482aa7fe0eaa",  # site_id
                "count": 6,
                "severity": {
                    "info": 0,
                    "warning": 0,
                    "minor": 1,
                    "major": 1,
                    "critical": 4
                }
            }
        ]
    }

    Returns:
        List[dict]: List of alert groups where each group contains:
            - name (str): The site_id
            - count (int): Total alert count for the site
            - severity (dict): Alert counts broken down by severity level
    """
    logger.info("Calling get_site_alerts")

    X_FROM = os.getenv("X_FROM")

    url = f'{ALERTMANAGER_URL}/alert-manager/api/v1/orgs/{org_id}/alerts/count'
    params = {
        "group_by": "subject.site_id",
        "group_by_severity": "true",
        "group_limit": "50",
        "severities": "SEVERITY_CRITICAL,SEVERITY_MINOR"
    }

    try:
        res = con.request(method="GET", url=url, headers={"X-FROM": X_FROM}, params=params)
        alerts_data = res.json()
        logger.info(f"Retrieved alerts grouped by site: {len(alerts_data.get('groups', []))} groups")
        return alerts_data.get("groups", [])
    except Exception as exp:
        logger.error(f"Failed to get sites with alerts: {exp}")
        return []


@validate_org_id
def execute_junos_rpc_sync(org_id: str, device_uuid: str, cli_operational_command: str) -> str:
    """
    Execute a Junos CLI operational command on a specified router.

    Usage Guidance:
    - Use this function only when the user explicitly requests execution of a Junos operational command.
    - Obtain the `device_uuid` using the `get_devices_sync` tool if not already known.

    :param org_id (str): ORG ID of the organization.
    :param device_uuid (str): UUID of the device (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"). Unique per device.
    :param cli_operational_command (str): The Junos CLI operational command to execute. Please follow these strict rules:
        1. Operational commands needs to be modified and can be executed as is
        2. Do not run commands that impact the device. e.g. reboot, restart, power-off, reset etc.
        3. To retrieve any configuration, follow below instruction
            a. "show configuration" should be part of the command
            b. "| display inheritance" should be appended to the command
        4. For configuration diff, use: "show configuration | compare rollback <rollback-id>", where <rollback-id> is between 1 and 49
    Returns:
        - The output of the executed command from the router, in JSON format.

    """

    if not validate_device_uuid(org_id=org_id, device_uuid=device_uuid):
        return "Invalid device UUID, fetch valid device UUID using the tool get_devices_sync"

    if _is_xml_command(cli_operational_command):
        return ("Blocked Junos RPC payload detected (%s). "
                "Use junos_config_set to change configuration instead." % ", ".join(BLOCKED_JUNOS_RPC_TAGS))

    blacklist_junos_command_regex = re.compile(BLACKLIST_REQUEST_JUNOS_COMMANDS_REGEX)
    match = blacklist_junos_command_regex.findall(cli_operational_command)
    if match:
        return "Disruptive commands %s not allowed" % match

    if USE_EXTERNAL_API is False:
        payload = {
            "device_info": {
                "UUID": device_uuid,
                "subSystem": "Netconf",
                "Organization": org_id,
            },
            "command": [f"<command>{cli_operational_command}</command>"]
        }
        try:
            res = con.request(method="POST", url=OCTALK_RPC, headers={"X-FROM": X_FROM}, json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to get device details {exp}: {sys.stderr}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to get device details {exp}: {sys.stderr}"
            logger.error(error)
            return error
    else:
        uuid = device_uuid
        payload = {
            "command": cli_operational_command
        }
        try:
            res = con.request(url=f"/api/v1/orgs/{org_id}/devices/{uuid}/execute_command_on_device", method="POST", json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to get device details {exp}: {sys.stderr}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to get device details {exp}: {sys.stderr}"
            logger.error(error)
            return error

    res.raise_for_status()
    details = res.json()
    return json.dumps(details)


@validate_org_id
def execute_junos_command(org_id: str, device_uuid: str, cli_operational_command: str) -> str:
    """
    Execute a Junos operational (show) CLI command on a router.

    PURPOSE: Use this tool ONLY for running Junos operational commands like show, monitor, ping, traceroute, etc.
    Do NOT use this tool for:
        - Configuring devices → use `junos_config_set` instead
        - Committing configuration → use `junos_config_commit` instead
        - Viewing configuration diffs → use `junos_config_diff` instead

    Args:
        org_id (str): ORG ID of the organization. Mandatory parameter.
        device_uuid (str): UUID of the device (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"). Use get_devices_sync to retrieve it.
        cli_operational_command (str): The Junos CLI operational command to execute. Please follow these strict rules:
            1. Do not run commands that impact the device. e.g. reboot, restart, power-off, reset etc.
            2. To view configuration use "show configuration ... | display inheritance".
                Example1: "show configuration interfaces ge-0/0/0 | display inheritance"
                Example2: "show configuration protocols ospf | display inheritance"
            3. Do NOT use this function for configuring the devices — use `junos_config_set` instead.

    Returns:
        str: Output of the executed command from the router, in JSON format.
    """
    if not validate_device_uuid(org_id=org_id, device_uuid=device_uuid):
        return "Invalid device UUID, fetch valid device UUID using the tool get_devices_sync"

    if _is_xml_command(cli_operational_command):
        return ("Blocked Junos RPC payload detected (%s). "
                "Use junos_config_set to change configuration instead." % ", ".join(BLOCKED_JUNOS_RPC_TAGS))

    blacklist_junos_command_regex = re.compile(BLACKLIST_REQUEST_JUNOS_COMMANDS_REGEX)
    match = blacklist_junos_command_regex.findall(cli_operational_command)
    if match:
        return "Disruptive commands %s not allowed" % match

    # Auto-quote unquoted regex patterns in pipe commands (e.g. | match up|down → | match "up|down")
    cli_operational_command = _quote_junos_pipe_patterns(cli_operational_command)

    if USE_EXTERNAL_API is False:
        payload = {
            "device_info": {
                "UUID": device_uuid,
                "subSystem": "Netconf",
                "Organization": org_id,
            },
            "command": [f"<command>{cli_operational_command}</command>"]
        }
        try:
            res = con.request(method="POST", url=OCTALK_RPC, headers={"X-FROM": X_FROM}, json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to get device details {exp}: {sys.stderr}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to get device details {exp}: {sys.stderr}"
            logger.error(error)
            return error
    else:
        payload = {
            "command": cli_operational_command
        }
        try:
            res = con.request(url=f"/api/v1/orgs/{org_id}/devices/{device_uuid}/execute_command_on_device", method="POST", json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to get device details {exp}: {sys.stderr}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to get device details {exp}: {sys.stderr}"
            logger.error(error)
            return error

    res.raise_for_status()
    details = res.json()
    return json.dumps(details)


@validate_org_id
def junos_config_diff(org_id: str, device_uuid: str, version: int = 1) -> str:
    """
    Get the configuration diff/delta/patch/changes between the current configuration and a rollback version on a Junos router.

    PURPOSE: Use this tool to VIEW configuration differences only. It does NOT modify any configuration.
    Do NOT use this tool for:
        - Configuring devices → use `junos_config_set` instead
        - Committing configuration → use `junos_config_commit` instead
        - Running operational commands → use `execute_junos_command` instead

    This function compares the current active configuration with a specified rollback configuration version,
    showing what has changed (added, removed, or modified) between the two versions.

    Recommended Workflow:
        1. Apply set commands using `junos_config_set`
        2. Review pending changes using `junos_config_diff(version=0)` to see uncommitted changes
        3. Commit using `junos_config_commit`

    Usage Guidance:
    - Use this function when the user wants to see configuration changes, differences, or what was modified.
    - Useful for auditing configuration changes, troubleshooting, or reviewing recent modifications.
    - Obtain the `device_uuid` using the `get_devices_sync` tool if not already known.

    Args:
        org_id (str): ORG ID of the organization. This is a mandatory parameter.
        device_uuid (str): UUID of the device (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"). Use get_devices_sync to retrieve it.
        version (int): The rollback version number to compare against (0-49). Default is 1.
                       - Version 0: Active configuration (shows uncommitted/pending changes)
                       - Version 1: Most recent saved configuration (last commit)
                       - Version 2: Second most recent saved configuration
                       - Higher numbers: Older configurations
                       Valid range: 0 to 49.

    Returns:
        str: JSON formatted string containing the configuration differences.
             - Lines starting with '+' indicate additions in current config
             - Lines starting with '-' indicate deletions from rollback config
             - Lines without prefix show context around changes

    Raises:
        Returns error message if:
        - Invalid device UUID is provided
        - Rollback version is out of valid range (0-49)
        - Device communication fails

    Examples:
        - Check uncommitted changes: junos_config_diff(org_id, device_uuid, 0)
        - Compare current config with last committed config: junos_config_diff(org_id, device_uuid, 1)
        - Compare current config with config from 2 commits ago: junos_config_diff(org_id, device_uuid, 2)
    """
    # Validate rollback version is within valid range
    if not isinstance(version, int) or version < 0 or version > 49:
        return "Invalid rollback version. Please provide a version number between 0 and 49."

    if not validate_device_uuid(org_id=org_id, device_uuid=device_uuid):
        return "Invalid device UUID, fetch valid device UUID using the tool get_devices_sync"

    # Construct the Junos CLI command for configuration diff
    cli_operational_command = f"show configuration | compare rollback {version}"

    if USE_EXTERNAL_API is False:
        payload = {
            "device_info": {
                "UUID": device_uuid,
                "subSystem": "Netconf",
                "Organization": org_id,
            },
            "command": [f"<command>{cli_operational_command}</command>"]
        }
        try:
            res = con.request(method="POST", url=OCTALK_RPC, headers={"X-FROM": X_FROM}, json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to get configuration diff: {exp}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to get configuration diff: {exp}"
            logger.error(error)
            return error
    else:
        payload = {
            "command": cli_operational_command
        }
        try:
            res = con.request(url=f"/api/v1/orgs/{org_id}/devices/{device_uuid}/execute_command_on_device", method="POST", json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to get configuration diff: {exp}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to get configuration diff: {exp}"
            logger.error(error)
            return error

    res.raise_for_status()
    details = res.json()
    return json.dumps(details)


@validate_org_id
def junos_config_set(org_id: str, device_uuid: str, set_commands: str) -> str:
    """
    Apply Junos configuration commands on a router. This stages the configuration in the candidate config
    but does NOT commit it. You MUST call `junos_config_commit` separately to activate the changes.

    PURPOSE: Use this tool to CONFIGURE a Junos device using set/delete commands.
    Do NOT use this tool for:
        - Running operational/show commands → use `execute_junos_command` instead
        - Viewing configuration diffs → use `junos_config_diff` instead
        - Committing configuration → use `junos_config_commit` instead

    Recommended Workflow:
        1. Call `junos_config_set` to stage configuration changes (this tool) — the pending diff is included automatically
        2. Call `junos_config_commit` to activate the configuration

    Args:
        org_id (str): ORG ID of the organization. Mandatory parameter.
        device_uuid (str): UUID of the device (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"). Use get_devices_sync to retrieve it.
                          Unique identifier per device. Use `get_device_list` to obtain this if unknown.
        set_commands (str): One or more Junos configuration commands to apply. Multiple commands must be separated by "\\n".
            Supported command prefixes:
            - "set ..." — to add or modify configuration
            - "delete ..." — to remove configuration

            Rules:
            1. Each command MUST start with "set " or "delete " prefix
            2. Do NOT include "commit" — use `junos_config_commit` separately
            3. Do NOT include "rollback" or "deactivate" commands
            4. Only standard Junos configuration mode commands are allowed

            Examples:
                Single set command:
                    "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24"
                Single delete command:
                    "delete interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24"
                Multiple mixed commands:
                    "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24\\ndelete protocols ospf area 0 interface ge-0/0/1\\nset protocols ospf area 0 interface ge-0/0/0"

    Returns:
        str: JSON formatted string containing the result of applying the commands.
             On success, returns the device response confirming the commands were staged,
             along with the pending configuration diff (no need to call junos_config_diff separately).
             On failure, returns an error message describing what went wrong.

    Important:
        - Changes are NOT active until `junos_config_commit` is called
        - The pending config diff is automatically included in the response — do NOT call junos_config_diff separately
    """
    if not validate_device_uuid(org_id=org_id, device_uuid=device_uuid):
        return "Invalid device UUID, fetch valid device UUID using the tool get_devices_sync"

    # Validate that all commands are set or delete commands
    commands = [cmd.strip() for cmd in set_commands.strip().split("\n") if cmd.strip()]
    if not commands:
        return "No valid commands provided. Please provide at least one set or delete command."

    allowed_prefixes = ("set ", "delete ")
    for cmd in commands:
        if not cmd.startswith(allowed_prefixes):
            return f"Invalid command: '{cmd}'. All commands must start with 'set ' or 'delete '. Do not include commit or rollback commands."

    # Block disallowed commands
    blacklist_config_keywords = ["rollback", "deactivate", "commit"]
    for cmd in commands:
        for keyword in blacklist_config_keywords:
            if keyword in cmd.lower():
                return f"Command containing '{keyword}' is not allowed. Only 'set' and 'delete' commands are permitted."


    if USE_EXTERNAL_API is False:
        # For internal API, send each set command wrapped in XML
        command_list = [f"<command>{cmd}</command>" for cmd in commands]
        payload = {
            "device_info": {
                "UUID": device_uuid,
                "subSystem": "Netconf",
                "Organization": org_id,
            },
            "command": command_list,
            "config_mode": True
        }
        try:
            res = con.request(method="POST", url=OCTALK_RPC, headers={"X-FROM": X_FROM}, json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to apply configuration: {exp}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to apply configuration: {exp}"
            logger.error(error)
            return error
    else:
        # Send commands directly — the API handles configure mode internally
        config_command = "\n".join(commands)
        payload = {
            "command": config_command
        }
        try:
            res = con.request(url=f"/api/v1/orgs/{org_id}/devices/{device_uuid}/execute_command_on_device", method="POST", json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to apply configuration: {exp}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to apply configuration: {exp}"
            logger.error(error)
            return error

    res.raise_for_status()
    details = res.json()

    # Automatically fetch the config diff to avoid a separate API call
    config_diff = None
    try:
        diff_result = junos_config_diff(org_id=org_id, device_uuid=device_uuid, version=0)
        config_diff = json.loads(diff_result) if isinstance(diff_result, str) else diff_result
    except Exception as exp:
        logger.warning(f"Failed to auto-fetch config diff: {exp}")

    result = {
        "status": "Configuration staged successfully. Use junos_config_commit to activate changes.",
        "commands_applied": commands,
        "device_response": details,
        "pending_config_diff": config_diff,
        "next_steps": "Review the pending_config_diff above, then commit with junos_config_commit"
    }
    return json.dumps(result)


@validate_org_id
def junos_config_commit(org_id: str, device_uuid: str, confirm_minutes: int = 0) -> str:
    """
    Commit the staged/candidate configuration on a Junos router to make it active.

    PURPOSE: Use this tool ONLY to commit previously staged configuration changes (applied via `junos_config_set`).
    Do NOT use this tool for:
        - Applying set commands → use `junos_config_set` instead
        - Running operational/show commands → use `execute_junos_command` instead
        - Viewing configuration diffs → use `junos_config_diff` instead

    Recommended Workflow:
        1. Apply set commands using `junos_config_set`
        2. Review pending changes using `junos_config_diff(version=0)`
        3. Commit using `junos_config_commit` (this tool)

    Args:
        org_id (str): ORG ID of the organization. Mandatory parameter.
        device_uuid (str): UUID of the device (e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"). Use get_devices_sync to retrieve it.
        confirm_minutes (int): Optional. If set to a value > 0, performs a "commit confirmed <minutes>".
                               The configuration will auto-rollback after the specified minutes unless
                               a follow-up `commit` is issued to confirm.
                               - 0 (default): Standard commit, changes are permanent immediately.
                               - 1-60: Commit confirmed with auto-rollback timer in minutes.
                               This is a safety mechanism — if the commit causes connectivity loss,
                               the device will automatically rollback after the timer expires.

    Returns:
        str: JSON formatted string containing the commit result.
             On success, confirms that the configuration has been committed and is now active.
             On failure, returns an error message describing what went wrong.

    Examples:
        - Standard commit: junos_config_commit(org_id, device_uuid)
        - Commit confirmed (10 min auto-rollback): junos_config_commit(org_id, device_uuid, confirm_minutes=10)
    """
    if not validate_device_uuid(org_id=org_id, device_uuid=device_uuid):
        return "Invalid device UUID, fetch valid device UUID using the tool get_devices_sync"

    # Validate confirm_minutes
    if not isinstance(confirm_minutes, int) or confirm_minutes < 0 or confirm_minutes > 60:
        return "Invalid confirm_minutes. Please provide a value between 0 and 60."

    # Build the commit command
    if confirm_minutes > 0:
        commit_command = f"commit confirmed {confirm_minutes}"
    else:
        commit_command = "commit"

    if USE_EXTERNAL_API is False:
        payload = {
            "device_info": {
                "UUID": device_uuid,
                "subSystem": "Netconf",
                "Organization": org_id,
            },
            "command": [f"<command>{commit_command}</command>"],
            "config_mode": True
        }
        try:
            res = con.request(method="POST", url=OCTALK_RPC, headers={"X-FROM": X_FROM}, json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to commit configuration: {exp}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to commit configuration: {exp}"
            logger.error(error)
            return error
    else:
        payload = {
            "command": commit_command
        }
        try:
            res = con.request(url=f"/api/v1/orgs/{org_id}/devices/{device_uuid}/execute_command_on_device", method="POST", json=payload)
        except requests.exceptions.RequestException as exp:
            error = f"RequestException failure. Failed to commit configuration: {exp}"
            logger.error(error)
            return error
        except Exception as exp:
            error = f"Failed to commit configuration: {exp}"
            logger.error(error)
            return error

    res.raise_for_status()
    details = res.json()
    commit_type = f"commit confirmed {confirm_minutes} minutes" if confirm_minutes > 0 else "commit"
    result = {
        "status": f"Configuration committed successfully ({commit_type}).",
        "device_response": details,
    }
    if confirm_minutes > 0:
        result["warning"] = (
            f"This is a confirmed commit. The configuration will auto-rollback in {confirm_minutes} minutes "
            f"unless a follow-up commit is issued to confirm the changes."
        )
    return json.dumps(result)


@validate_org_id
def get_device_latest_config(org_id: str, device_id: str) -> str:
    """
    Retrieves the latest committed device configuration from Routing Director.
    Routing Director caches the most recent committed configuration per managed
    device, so this avoids running a CLI command on the device itself.

    :param org_id: The organization ID
    :param device_id: The device UUID (e.g. f47ac10b-58cc-4372-a567-0e02b2c3d479)
    :return: JSON string. On success: {"device_id":..., "config":<dict-or-str>}.
             On failure: {"error":..., "details":...}
    """
    logger.info("get_device_latest_config")
    uuid = device_id if device_id else ""
    if not uuid:
        return json.dumps({"error": "device_id is required"})
    try:
        if USE_EXTERNAL_API is False:
            resp = con.request(method="GET",
                               url=f"{PAPI_URL}internal/orgs/{org_id}/devices/{uuid}/latest_config",
                               headers={"X-FROM": X_FROM})
        else:
            resp = con.request(method="GET",
                               url=f"/api/v1/orgs/{org_id}/devices/{uuid}/latest_config")
    except requests.exceptions.RequestException as exp:
        return json.dumps({"error": "Failed to fetch latest_config", "details": str(exp)})
    if resp.status_code != 200:
        return json.dumps({"error": f"HTTP {resp.status_code}", "details": resp.text[:500]})
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    return json.dumps({"device_id": uuid, "config": body}, default=str)

