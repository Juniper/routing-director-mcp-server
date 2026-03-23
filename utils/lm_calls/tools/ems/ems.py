import os
import sys
import json
import logging
import re
import requests
from typing import Optional, List
import urllib.parse
from utils.lm_calls.tools.constants import uuid_regex
from utils.lm_calls.paragon.constants import (PAPI_URL, con, USE_EXTERNAL_API, ALERTMANAGER_URL, X_FROM)
from utils.lm_calls.tools.ems.config_template import ConfigTemplate
from utils.lm_calls.tools.fh import list_available_vpns

alert_severities = ["SEVERITY_CRITICAL", "SEVERITY_MAJOR", "SEVERITY_MINOR", "SEVERITY_WARNING", "SEVERITY_INFO"]

log_level = os.getenv("LOG_LEVEL", "ERROR").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.ERROR))
logger = logging.getLogger(__name__)

tools_dir = os.path.dirname(os.path.dirname(__file__))
assets_dir = os.path.join(tools_dir, "assets")
ems_openapi_file = os.path.join(assets_dir, "ems_openapi.json")
all_apis_file = os.path.join(assets_dir, "all_apis.json")


def clean_mac(mac: str) -> str:
    """Cleans MAC address by removing separators.

    Args:
        mac: MAC address in format XXXXXXXXXXXX (12 chars) or XX:XX:XX:XX:XX:XX (17 chars)

    Returns:
        Cleaned MAC address in format XXXXXXXXXXXX (12 chars)
    """
    if len(mac) == 36:
        return mac
    return mac.translate(str.maketrans('', '', ':-')).lower()

def get_mac_uuid(mac: str) -> str:
    """Convert MAC address to UUID format.

    Args:
        mac: MAC address in format XXXXXXXXXXXX (12 chars) or XX:XX:XX:XX:XX:XX (17 chars)

    Returns:
        UUID string in format 00000000-0000-0000-1000-XXXXXXXXXXXX
    """
    # received UUID format, return as-is
    if len(mac) == 36:
        return mac

    # Normalize MAC address by removing separators
    normalized_mac = clean_mac(mac=mac)

    # Return UUID format if normalized MAC is 12 characters, otherwise return as-is
    if len(normalized_mac) == 12:
        return f"00000000-0000-0000-1000-{normalized_mac}"
    return mac


def get_site_id(org_id: str, site_name: str) -> str:
    url = f'{PAPI_URL}internal/orgs/{org_id}/sites'
    try:
        res = con.request(method="GET", url=url, headers={"X-FROM": X_FROM})
    except requests.exceptions.RequestException as exp:
        err_msg = 'Failed to get site details'
        print(f"{err_msg}: {exp}", file=sys.stderr)
        return err_msg
    else:
        details = res.json()
        for site in details:
            if site.get("name") == site_name:
                return site.get("id")
    return "Failed to get site details"


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


def get_devices_sync(org_id: str, vendor: str, host: str, model:str, site_id:str, mac:str) -> str:
    """
    Retrieves the list of devices from the Routing Director. You can also fetch the device details like alert, mac-address, connected/disconnected, device model type. 
    Filter devices using one or a combination of optional parameters.

    :param org_id: The organization ID. compulsory parameter.
    :param vendor: Filter by device vendor, possible values are "Juniper Networks", "Cisco", "Nokia". Optional Parameter.
    :param host: DNS host name or IP of the device. Optional parameter.
    :param model: Filter by device model (e.g., "MX960"). Optional parameter.
    :param site_id: Filter by site ID (e.g., "f2199f26-60cc-4ebc-a73b-dd93a1920d3c"). Optional parameter.
    :param mac: Filter by mac (e.g., "2c6bf5660700"). Optional parameter.
    :return: JSON string containing the list of devices
    """
    limit = 50
    params = {
        "limit": limit,
        "offset": 0,
    }
    if model:
        params["model"] = model + "*"
    if mac:
        if re.match(uuid_regex, mac):
            mac = mac[-12:]
        mac = mac.replace(":", "").replace("-", "")
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
            "mac": dev.get("mac", ""),
            "model": dev.get("model", ""),
            "alerts": {"critical": dev.get("alert_counts_critical", 0), "major": dev.get("alert_counts_major", 0), "minor": dev.get("alert_counts_minor", 0)},
            "connected": dev.get("connected", False)
        }

        devices.append(device)
    num_devices = details.get("total", 0)
    if num_devices > limit:
        comment = (f"There are a total of {num_devices} devices available. Displaying the {limit} results. "
                   f"For more specific results, please search by model name, vendor, site ID, mac, host.")
    else:
        comment = f"There are a total of {num_devices} devices available. Displaying all the results."
    res = {
        "total_devices": details.get("total", 0),
        "devices": devices,
        "comment": comment,
    }
    res["instructions"] = f"""
    Do not send only the MAC address in the response.
    Include the device’s IP address or hostname as well for proper identification.
    """
    devices_str = json.dumps(res)

    return devices_str


def get_device_info(org_id: str, device_id: str) -> str:
    """
    Retrieves the device information from the Routing Director
    :param org_id: The organization ID
    :param device_id: The device ID. This is UUID of the device
    :return: JSON string containing the device information
    """
    logger.info("get_device_info")
    # device_id is either UUID 00000000-0000-0000-1000-2c6bf5975600
    if len(device_id) == 36:
        device_id = device_id.split("-")[-1]
    params = {
        "mac": device_id
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
    return json.dumps(resp, indent=2)


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
    return json.dumps(resp, indent=2)


def get_alerts_count(org_id: str, *, router_mac: str="", site_id: str="", alert_type: str="", severity: str="SEVERITY_MINOR",
                     include_acknowledged: bool=False, vpn_uuid: str = "", extra_params: dict = {}, return_data: bool = False) -> str:
    """
    Use this function to get the count of available active alerts for all devices or a specific device of the org. It also provides the count of alerts per severity value.

    Args:
        org_id(str): ORG ID of the organization.
        router_mac(str): MAC address without ":" or "-" of the router
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
    severity = severity if severity in alert_severities else "SEVERITY_MINOR"

    params = {
        "group_by_severity": "true",
        "severity": severity
    }

    if site_id:
        if not (site_id and re.match(uuid_regex, site_id)):
            site_id = get_site_id(org_id=org_id, site_name=site_id)
            if site_id == "Failed to get site details":
                return site_id
        params["subject.site_id"] = site_id
    if alert_type:
        params["type"] = alert_type
    if include_acknowledged:
        params["include_acked"] = "true"
    if router_mac:
        params["subject.device_id"] = get_mac_uuid(mac=router_mac)
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
    except requests.exceptions.RequestException as exp:
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


def get_alerts_for_device(org_id: str, mac: str) -> str:
    """
    Retrieves the alerts for a device , irrespective of site severity and category.
    Use this function to get the alerts for a device.
    The alerts are grouped by category and severity.
    :param org_id: The organization ID
    :param device_id: The device ID. This is UUID of the device
    :return: JSON string containing the alerts grouped by category with severity counts
    """
    if USE_EXTERNAL_API is True:
        return "Not Implemented"

    # Call the alert-manager API with device_id as query parameter
    url = f"{ALERTMANAGER_URL}/alert-manager/api/v1/orgs/{org_id}/alerts"
    params = {
        "subject[device_id]": get_mac_uuid(mac)
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
        "device_id": mac,
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


def get_alerts_list(org_id: str, *, router_mac: str="", site_id: str="", vpn_uuid: str="", alert_type: str="", severity: str="SEVERITY_MAJOR", include_acknowledged: bool=False, extra_params: dict = {}) -> str:
    """
    Use this function if list of available active alerts for the org or a single device is required. Up to 50 alerts will be returned.
    Don't call this function if the count of alerts is required. Use get_alerts_count instead.
    Return the list of alerts do not summarize the alerts unless asked by user.

    IMPORTANT: Always use UUIDs for vpn_uuid parameter, never use names

    Args:
        org_id(str): ORG ID of the organization.
        router_mac(str): MAC address without ":" or "-" of the router
        site_id(str): Filter by site ID, if you have site (e.g., "f2199f26-60cc-4ebc-a73b-dd93a1920d3c")
        vpn_uuid(str): Filter by VPN UUID only. Must be the actual UUID/instance_uuid in format like "f2199f26-60cc-4ebc-a73b-dd93a1920d3c". Do NOT use VPN name - only use the UUID identifier.
        alert_type(str): Filter by alert type (e.g., "routing.isis", "routing", "hardware.fpc.pfe.pfe-bad-route-discard", "hardware", "trust.vulnerability.advisory")
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
        if site_id and re.match(uuid_regex, site_id):
            params["subject[site_id]"] = site_id
        else:
            params["subject[site_id]"] = get_site_id(org_id=org_id, site_name=site_id)
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
    if router_mac:
        if re.match(uuid_regex, router_mac):
            params["subject[device_id]"] = router_mac
        else:
            params["subject[device_id]"] = get_mac_uuid(mac=router_mac)

    # Set extra parameters if any
    for k,v in extra_params.items():
        params[k] = v

    try:
        if USE_EXTERNAL_API is False:
            url = f"{ALERTMANAGER_URL}/alert-manager/api/v1/orgs/{org_id}/alerts"
            res = con.request(method="GET", url=url, headers={"X-FROM": X_FROM}, params=params)
        else:
            res = con.request(url=f"/alert-manager/api/v1/orgs/{org_id}/alerts", method="GET", params=params)
    except requests.exceptions.RequestException as exp:
        error_msg = f"Failed to get alert details for the organization {org_id}: {exp}"
        return json.dumps({"error": error_msg})
    else:
        res = res.json()

    if not res:
        return "No alerts found"

    res["instructions"] = "Resolve all the device_id to device names in alerts using get_device_list tool from papi_agent"

    return json.dumps(res)

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