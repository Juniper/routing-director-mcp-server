import functools
import os
import json
import logging
import requests
import sys
from utils.lm_calls.paragon.constants import EOP_HOST, PAPI_URL, con, USE_EXTERNAL_API


log_level = os.getenv("LOG_LEVEL", "ERROR").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.ERROR))
logger = logging.getLogger(__name__)

def get_full_eop_host():
    """
    Ensures EOP_HOST has 'http://' or 'https://' prefix based on deployment.
    If not present, 'https://' is added by default.
    """

    if not (EOP_HOST.startswith('http://') or EOP_HOST.startswith('https://')):
        return f'https://{EOP_HOST}'

    return EOP_HOST


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


def validate_device_mac(org_id: str, device_mac: str):
    logger.info("Validating the device mac {}".format(device_mac))
    mac = clean_mac(mac=device_mac)
    params = {
        "id": get_mac_uuid(mac=mac),
    }

    try:
        if USE_EXTERNAL_API is False:
            res = con.request(url=f"{PAPI_URL}internal/orgs/{org_id}/device/profiles/search", params=params, method="GET")
        else:
            res = con.request(url=f"/api/v1/orgs/{org_id}/device/profiles/search", params=params, method="GET")
    except requests.exceptions.RequestException as exp:
        print(f"Failed to get device details {exp}", file=sys.stderr)
        return "Failed to get device details"
    else:
        details= res.json()
    device_exists = details.get("total") == 1
    if not device_exists:
        logger.error(f"Device with mac {device_mac} does not exist")
    return device_exists


def validate_org_id(func):
    """
    Decorator that validates the ``org_id`` argument of the wrapped function
    against the list of valid org IDs known to the routing director client
    (``con.org_id``) before the function is executed.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        org_id = kwargs.get("org_id") if "org_id" in kwargs else (args[0] if args else None)
        if org_id is not None:
            if USE_EXTERNAL_API is False:
                valid_org_id = getattr(con, "org_id", "")
                if valid_org_id and (org_id != valid_org_id):
                    error_msg = f"Invalid org_id: {org_id}. The provided organization ID is not valid."
                    logger.error(error_msg)
                    return error_msg
            else:
                user_configured_org_id = getattr(con, "org_id", "")
                if user_configured_org_id and (org_id != user_configured_org_id):
                    # If user has configured the org_id in config.json verify if it is the same org id used in the tool call called
                    error_msg = f"The organization ID '{org_id}' cannot be used, this MCP server is configured for organization ID '{user_configured_org_id}'. Use '{user_configured_org_id}' and retry."
                    logger.error(error_msg)
                    return error_msg
                elif not user_configured_org_id:
                    # If user has not configured the org_id in config.json verifying if the org_id is a valid one as is
                    # part of all the org_ids the user has access to. Fetching all the org_ids the user has access to by
                    # calling /api/v1/self and checking if the org_id is part of it.
                    all_org_ids = []
                    resp = con.request(method="GET", url="/api/v1/self")
                    resp = resp.json()
                    for privilege in resp.get('privileges', []):
                        all_org_ids.append(privilege.get("org_id", ""))
                    if all_org_ids and org_id not in all_org_ids:
                        error_msg = f"The provided organization ID '{org_id}' is either not valid or the user does not have permission to access it."
                        logger.error(error_msg)
                        return error_msg
        return func(*args, **kwargs)
    return wrapper




