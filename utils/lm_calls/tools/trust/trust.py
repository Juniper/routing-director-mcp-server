import os
import sys
import json
import logging
import re
import base64
import requests
from typing import Optional, List, Dict, Any
import urllib.parse
from utils.lm_calls.agent_directives import attach_directives
from utils.lm_calls.tools.helper import validate_org_id
from utils.lm_calls.paragon.constants import (TRUST_URL, con, USE_EXTERNAL_API,  X_FROM)

logger = logging.getLogger(__name__)

FILTER_KEY = "selection.filtering.filter"
DEFAULT_PROFILE = "xccdf_org.cisecurity.benchmarks_profile_Level_1"

def _handle_trust_error(context: str, exc: requests.exceptions.RequestException) -> Dict[str, Any]:
    logger.error("%s: %s", context, exc, exc_info=True)
    return {"error": context, "details": str(exc)}

def _add_filter(params: dict, clause: str, op: str = "AND") -> None:
    if FILTER_KEY in params and params[FILTER_KEY]:
        params[FILTER_KEY] += f" {op} {clause}"
    else:
        params[FILTER_KEY] = clause

def _trust_request(
        org_id: str,
        method: str,
        path: str,
        params: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    encoded_params = urllib.parse.urlencode(params or {})
    query = f"?{encoded_params}" if encoded_params else ""
    try:
        if not USE_EXTERNAL_API:
            headers = {"X-FROM": X_FROM, "Grpc-Metadata-Tenant-Id": org_id}
            url = f"{TRUST_URL}{path}{query}"
            res = con.request(method=method, url=url, headers=headers, json=json_body)
        else:
            url = f"/trust/api/v1.1alpha/{org_id}{path}{query}"
            res = con.request(method=method, url=url, json=json_body)
    except requests.exceptions.RequestException as exp:
        return _handle_trust_error(f"Trust request failed: {method} {path}", exp)
    return res.json()


@validate_org_id
def get_trust_devices(org_id:str, device_name: Optional[str] = None, device_ems_uuid: Optional[str] = None) -> dict:
    """
    Retrieve trust devices. For all compliance related tests targetIDs needs to be retrieved from trust devices.

    param org_id: ORG ID of the organization. This is a mandatory parameter.
    param device_name: Name of the device. This is an optional parameter.
    param device_ems_uuid: EMS UUID of the device. This is an optional parameter.
    return: Dictionary containing trust device details
    """
    params = {}
    _add_filter(params=params, clause=f"host_name=\"{device_name}\"")  if device_name else None
    _add_filter(params=params, clause=f"ems_uuid=\"{device_ems_uuid}\"", op="OR") if device_ems_uuid else None
    # if device_name:
    #     params['selection.filtering.filter'] = f"host_name=\"{device_name}\""
    # if device_ems_uuid:
    #     if 'selection.filtering.filter' in params:
    #         params['selection.filtering.filter'] += f" OR ems_uuid=\"{device_ems_uuid}\""
    #     else:
    #         params['selection.filtering.filter'] = f"ems_uuid=\"{device_ems_uuid}\""

    return _trust_request(org_id=org_id, method="GET", path="/devices", params=params)


@validate_org_id
def list_compliance_scans(
        org_id: str,
        scan_name: Optional[str] = None,
        device_name: Optional[str] = None) -> dict:
    """
    List compliance scans for a given device.

    param org_id: ORG ID of the organization. This is a mandatory parameter.
    param scan_name: Compliance scan name. This is an optional parameter.
    param device_name: Name or IP of the device on which scan is run. This is an optional parameter.
    return: Dictionary containing compliance scan details
    """
    params = {}
    _add_filter(params=params, clause=f"request_name=\"*{scan_name}*\"")  if scan_name else None
    _add_filter(params=params, clause=f"(host_name=\"{device_name}\" OR address =\"{device_name}\" OR friendly_name=\"{device_name}\")")  if device_name else None

    return _trust_request(org_id=org_id, method="GET", path="/compliance/scans", params=params)


@validate_org_id
def get_compliance_scan_details(
        org_id: str,
        scan_id: str) -> dict:
    """
    Retrieve compliance scan by scan ID. Prefer this over listing all scans and filtering if scan_id is known.

    param org_id: ORG ID of the organization. This is a mandatory parameter.
    param scan_id: Scan ID of the compliance scan. This is a mandatory parameter.
    return: Dictionary containing compliance scan details
    """
    details =  _trust_request(org_id=org_id, method="GET", path=f"/compliance/scans/{scan_id}")
    if "error" not in details and "context" not in details:
        attach_directives(details, """If details of a particular scan is requested, then give detailed summary.
        1) Retrieve "results" from the scan
        2) There can be multiple objects in results. For each result object get resultDocId. Call get_compliance_doc with that ID to retrieve the detailed scan results
        3) Based on the data summarize the compliance status of the devices
        """)
    return details


@validate_org_id
def list_compliance_scan_benchmark_docs(
        org_id: str,
        name: Optional[str] = None,
        source: Optional[str] = None,
        version: Optional[str] = None) -> dict:
    """
    List compliance scan benchmark documents.

    param org_id: ORG ID of the organization. This is a mandatory parameter.
    param name: Name of the benchmark document. This is an optional parameter.
    param source: Source of the benchmark document. This is an optional parameter.
    param version: Version of the benchmark document. This is an optional parameter.
    return: Dictionary containing compliance scan benchmark documents
    """
    params = {}
    _add_filter(params=params, clause=f"name=\"*{name}*\"")  if name else None
    _add_filter(params=params, clause=f"location=\"/benchmark/{source}*\"")  if source else None
    _add_filter(params=params, clause=f"version=\"*{version}*\"")  if version else None

    return _trust_request(org_id=org_id, method="GET", path=f"/compliance/documents/search", params=params)


@validate_org_id
def get_compliance_doc(
        org_id: str,
        document_id: str) -> dict:
    """
    Retrieve compliance document by document ID.
    Document can be one of:
      1) benchmark document
      2) result document(resultDocId) from complaince scan or
      3) any other compliance document.

    param org_id: ORG ID of the organization. This is a mandatory parameter.
    param document_id: Document ID of the compliance document. This is a mandatory parameter.
    return: Dictionary containing compliance document details
    """
    # Trust uses the document ID in the URL and the document ID could contain special characters.
    # Encoding the document ID to make it URL safe.
    encoded_document_id = urllib.parse.quote(document_id, safe='')
    details = _trust_request(org_id=org_id, method="GET", path=f"/compliance/documents/{encoded_document_id}")
    if "document" in details:
        document_data = details.get("document", {}).get("document", "")
        if document_data:
            details["document"]["document"] = str(base64.b64decode(document_data))
    return details


@validate_org_id
def create_compliance_scan(
        org_id: str,
        scan_name: str,
        device_target_ids: List[str],
        benchmark_doc_id: str,
        profile: Optional[str] = DEFAULT_PROFILE) -> dict:
    """
    Create a compliance scan for given devices.

    param org_id: ORG ID of the organization. This is a mandatory parameter.
    param scan_name: Name of the compliance scan. This is a mandatory parameter.
    param device_target_ids: List of device tagetIDs on which the scan needs to be run. These needs to be retrieved using get_trust_devices. This is a mandatory parameter.
    param benchmark_doc_id: Benchmark document ID to be used for the scan. This is a mandatory parameter.
    param profile: Profile to be used for the scan. This is a optional parameter. Can be one of 'xccdf_org.cisecurity.benchmarks_profile_Level_1', 'xccdf_org.cisecurity.benchmarks_profile_Level_2
    return: Dictionary containing compliance scan creation response
    """
    body = {
        "details": {
            "name": scan_name,
            "targetIds": device_target_ids,
            "benchmarkDoc": benchmark_doc_id,
            "profile": profile
        },
    }
    return _trust_request(org_id=org_id, method="POST", path=f"/compliance/scans", json_body=body)
