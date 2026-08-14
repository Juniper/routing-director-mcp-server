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


# -----------------------------------------------------------------------------
# SIRT vulnerability advisories
# -----------------------------------------------------------------------------

@validate_org_id
def list_device_advisory_ids(org_id: str, trust_device_id: str) -> Dict[str, Any]:
    """
    List the SIRT advisory IDs that apply to a specific trust device.

    The trust subsystem uses its own per-device UUID (the `id` field returned
    by get_trust_devices), not the EMS device UUID. Use the EMS UUID's last
    12 hex characters (the device MAC) to match a trust device's `macAddress`,
    or match `sourceId` directly against the EMS UUID, then pass the trust
    device's `id` here.

    param org_id: ORG ID of the organization. This is a mandatory parameter.
    param trust_device_id: The trust subsystem's device id.
    return: {"advisoryIds": [...]} or an error dict.
    """
    return _trust_request(org_id=org_id, method="GET",
                          path=f"/vulnerability/device/{trust_device_id}")


@validate_org_id
def get_advisory_details(org_id: str, advisory_id: str) -> Dict[str, Any]:
    """
    Fetch the full definition of a single SIRT advisory by ID (sirtId/JSAxxxxx
    is NOT the ID accepted here; use the UUID returned by
    list_device_advisory_ids or list_vulnerability_advisories).

    The response includes the advisory definition with: sirtId (JSA number),
    title, conditions, description, workaround, productCategories,
    affectedReleases, cvssScore, severity.

    param org_id: ORG ID of the organization. This is a mandatory parameter.
    param advisory_id: The advisory UUID.
    return: The advisory definition dict, or an error dict.
    """
    encoded = urllib.parse.quote(advisory_id, safe='')
    return _trust_request(org_id=org_id, method="GET",
                          path=f"/vulnerability/advisories/{encoded}")


@validate_org_id
def get_vulnerability_statistics(org_id: str) -> Dict[str, Any]:
    """
    Get current org-wide vulnerability statistics from the trust component.
    Useful as a fast first call to see if any SIRT advisories apply at all.

    param org_id: ORG ID of the organization. This is a mandatory parameter.
    return: {"currentStats": {...}}
    """
    return _trust_request(org_id=org_id, method="GET",
                          path=f"/vulnerability/statistics/current")


# Advisory keyword <-> live-config keyword pairs used by the cross-reference
# orchestrator. Heuristic only — both sides must match before a finding is
# flagged as "exposed". Keep the list narrow to limit false positives.
_FEATURE_RULES = [
    ("snmp",        r"\bSNMP\b",                                       r"\bsnmp\b"),
    ("dhcp_relay",  r"\bDHCP\b.*\brelay\b|\bjdhcpd\b|\boption[- ]?82\b", r"dhcp-relay|forwarding-options[^}]*dhcp"),
    ("dhcp",        r"\bDHCP\b",                                       r"\bdhcp(-relay|-local-server|-security)?\b"),
    ("netconf",     r"\bNETCONF\b",                                    r"\bnetconf\b"),
    ("ssh",         r"\bSSH\b|\bsshd\b",                               r"\bssh\b"),
    ("telnet",      r"\btelnet\b",                                     r"\btelnet\b"),
    ("jweb_http",   r"\bJ-?Web\b|web-management|\bhttps?\b",           r"web-management|\bhttps?\b"),
    ("rest_api",    r"\bREST\b\s*API|\bjsd\b",                         r"\brest\b"),
    ("ftp",         r"\bFTP\b",                                        r"\bftp\b"),
    ("bgp",         r"\bBGP\b",                                        r"\bbgp\b"),
    ("ospf",        r"\bOSPF(v3)?\b",                                  r"\bospf3?\b"),
    ("isis",        r"\bIS-?IS\b",                                     r"\bisis\b"),
    ("ldp",         r"\bLDP\b",                                        r"\bldp\b"),
    ("rsvp",        r"\bRSVP\b",                                       r"\brsvp\b"),
    ("mpls",        r"\bMPLS\b",                                       r"\bmpls\b"),
    ("pim",         r"\bPIM\b",                                        r"\bpim\b"),
    ("evpn",        r"\bEVPN\b",                                       r"\bevpn\b|encapsulation vxlan"),
    ("ipsec_ike",   r"\bIPSec\b|\bIKE\b",                              r"\b(ipsec|ike)\b"),
    ("macsec",      r"\bMACsec\b",                                     r"\bmacsec\b"),
    ("dot1x",       r"\b802\.1[xX]\b|\bdot1x\b",                       r"\bdot1x\b|\b802\.1[xX]\b"),
    ("l2tp",        r"\bL2TP\b",                                       r"\bl2tp\b"),
    ("pppoe",       r"\bPPPoE\b",                                      r"\bpppoe\b"),
    ("radius",      r"\bRADIUS\b",                                     r"\bradius\b"),
    ("tacacs",      r"\bTACACS\b",                                     r"\btacacs\b"),
    ("ntp",         r"\bNTP\b",                                        r"\bntp\b"),
    ("sampling",    r"\bsFlow\b|\bjflow\b|\bsampling\b",               r"\bsampling\b|\bsflow\b"),
    ("port_mirror", r"port-?mirror|\banalyzer\b",                      r"\banalyzer\b|port-mirror"),
]
_FEATURE_RULES_COMPILED = [
    (name, re.compile(adv_rx, re.I), re.compile(cfg_rx, re.I))
    for name, adv_rx, cfg_rx in _FEATURE_RULES
]


def _advisory_text(adv: dict) -> str:
    if not isinstance(adv, dict):
        return ""
    d = (adv.get("advisory") or {}).get("definition") or {}
    parts = [d.get("title", ""), d.get("conditions", ""),
             d.get("description", ""), d.get("workaround", "")]
    parts.append(" ".join(d.get("productCategories") or []))
    return " ".join(p for p in parts if p)


@validate_org_id
def correlate_sirt_with_active_config(
        org_id: str,
        device_ids: Optional[List[str]] = None,
        include_unmatched: bool = False,
) -> Dict[str, Any]:
    """
    End-to-end SIRT-vs-active-config cross reference.

    For every device that has at least one trust vulnerability advisory:
      1. Look up the device's EMS profile (hostname, mac, management_ip).
      2. Bridge to its trust subsystem id via macAddress / sourceId / address.
      3. Fetch the list of advisory IDs that apply.
      4. Fetch each advisory definition (sirtId, title, workaround, ...).
      5. Pull the device's latest_config from Routing Director.
      6. Heuristically flag advisories whose subject overlaps with features
         that are actually enabled in the running configuration.

    Output is a structured report — use this single call instead of orchestrating
    get_trust_devices + list_device_advisory_ids + get_advisory_details +
    get_device_latest_config manually.

    param org_id: ORG ID of the organization. Mandatory.
    param device_ids: Optional list of EMS device UUIDs to restrict the scan to.
                      If omitted, every device with at least one SIRT advisory
                      is included.
    param include_unmatched: When True, advisories that apply to the device but
                             have no feature overlap with the running config are
                             listed under "unmatched_findings". Default False
                             to keep the payload small.
    return: {
      "summary": {...},
      "devices": [
        {
          "hostname", "management_ip", "ems_uuid", "trust_id",
          "model", "firmware",
          "advisory_count", "config_bytes",
          "exposed_findings": [
            {"advisoryId","sirtId","title","matches":[...],"workaround"},
          ],
          "unmatched_findings": [ ... ]   # only when include_unmatched=True
        }
      ]
    }
    """
    from utils.lm_calls.tools.ems.ems import get_device_latest_config
    from utils.lm_calls.tools.trust.junos_version import (
        recommend_upgrade, normalize_severity, extract_config_commands,
    )

    # 1. Pull trust device list once to build EMS↔trust bridges.
    trust_devs_resp = get_trust_devices(org_id=org_id)
    trust_items = (trust_devs_resp.get("devices") or trust_devs_resp.get("data")
                   or trust_devs_resp.get("results") or []) if isinstance(trust_devs_resp, dict) else []
    trust_by_ems = {}
    trust_by_mac = {}
    trust_by_addr = {}
    for d in trust_items:
        tid = d.get("id") or d.get("targetId") or d.get("deviceId")
        if not tid:
            continue
        if d.get("sourceId"):
            trust_by_ems[d["sourceId"]] = tid
        if d.get("macAddress"):
            trust_by_mac[d["macAddress"].lower()] = tid
        if d.get("address"):
            trust_by_addr[d["address"]] = tid

    # 2. Decide which EMS UUIDs to look at.
    candidate_ems_uuids = []
    if device_ids:
        candidate_ems_uuids = list(device_ids)
    else:
        # Use trust source IDs as the candidate set (devices known to trust).
        candidate_ems_uuids = [d.get("sourceId") for d in trust_items if d.get("sourceId")]

    # 3. Per device: profile + advisory IDs + advisories + latest_config + correlate.
    adv_cache: Dict[str, dict] = {}

    def _ems_profile(ems_uuid: str) -> Optional[dict]:
        try:
            if USE_EXTERNAL_API is False:
                r = con.request(method="GET",
                                url=f"/internal/orgs/{org_id}/device/profiles/search",
                                params={"id": ems_uuid}, headers={"X-FROM": X_FROM})
            else:
                r = con.request(method="GET",
                                url=f"/api/v1/orgs/{org_id}/device/profiles/search",
                                params={"id": ems_uuid})
        except requests.exceptions.RequestException as exp:
            logger.warning("EMS profile lookup failed for %s: %s", ems_uuid, exp)
            return None
        if r.status_code != 200:
            logger.warning("EMS profile lookup for %s returned HTTP %s", ems_uuid, r.status_code)
            return None
        try:
            res = r.json().get("results") or []
        except Exception as exp:
            logger.warning("EMS profile response for %s was not JSON: %s", ems_uuid, exp)
            return None
        return res[0] if res else None

    devices_out = []
    total_exposed = 0
    for ems_uuid in candidate_ems_uuids:
        prof = _ems_profile(ems_uuid) or {}
        mac = (prof.get("mac") or "").lower()
        mgmt_ip = prof.get("management_ip") or prof.get("address")
        trust_id = (trust_by_ems.get(ems_uuid)
                    or trust_by_mac.get(mac)
                    or trust_by_addr.get(mgmt_ip))

        adv_ids: List[str] = []
        if trust_id:
            adv_resp = list_device_advisory_ids(org_id=org_id, trust_device_id=trust_id)
            if isinstance(adv_resp, dict):
                adv_ids = adv_resp.get("advisoryIds") or adv_resp.get("ids") or []

        if not adv_ids:
            # Device has no advisories; only include if it was explicitly requested.
            if device_ids:
                devices_out.append({
                    "hostname": prof.get("name") or prof.get("hostname"),
                    "management_ip": mgmt_ip,
                    "ems_uuid": ems_uuid, "trust_id": trust_id,
                    "model": prof.get("model"), "firmware": prof.get("version"),
                    "advisory_count": 0,
                    "exposed_findings": [],
                })
            continue

        # latest_config
        cfg_text = ""
        cfg_error = None
        cfg_raw = get_device_latest_config(org_id=org_id, device_id=ems_uuid)
        try:
            cfg_obj = json.loads(cfg_raw)
        except Exception:
            cfg_obj = {"error": "non-JSON response"}
        if isinstance(cfg_obj, dict) and "error" in cfg_obj and "config" not in cfg_obj:
            cfg_error = cfg_obj.get("error")
        else:
            inner = cfg_obj.get("config") if isinstance(cfg_obj, dict) else None
            cfg_text = inner if isinstance(inner, str) else json.dumps(inner) if inner else ""

        exposed = []
        unmatched = []
        for aid in adv_ids:
            if aid not in adv_cache:
                adv_cache[aid] = get_advisory_details(org_id=org_id, advisory_id=aid)
            adv = adv_cache[aid]
            # Skip advisory fetches that returned an error envelope rather than a
            # real definition. We log once per advisory so the report doesn't end
            # up with rows of null sirtId/title.
            if not isinstance(adv, dict) or not (adv.get("advisory") or {}).get("definition"):
                logger.warning("Advisory %s missing definition; skipping (response=%r)",
                               aid, adv if not isinstance(adv, dict) else list(adv.keys()))
                continue
            d = (adv.get("advisory") or {}).get("definition") or {}
            text = _advisory_text(adv)
            matches: List[str] = []
            if cfg_text:
                for name, adv_rx, cfg_rx in _FEATURE_RULES_COMPILED:
                    if adv_rx.search(text) and cfg_rx.search(cfg_text):
                        matches.append(name)
            affected_versions = d.get("affectedVersions") or []
            workaround_text = (d.get("workaround") or "")
            entry = {
                "advisoryId": aid,
                "sirtId": d.get("sirtId"),
                "title": d.get("title"),
                "severity": normalize_severity(d.get("severityLevel"), d.get("cvssScore")),
                "cvssScore": d.get("cvssScore"),
                "cveIds": d.get("cveIds") or [],
                "matches": matches,
                "workaround": workaround_text[:1500],
                "configCommands": extract_config_commands(workaround_text),
                "affectedVersions": affected_versions,
            }
            (exposed if matches else unmatched).append(entry)
        total_exposed += len(exposed)
        firmware = prof.get("version")
        pooled_affected = set()
        for e in exposed:
            pooled_affected.update(e.get("affectedVersions") or [])
        upgrade = recommend_upgrade(firmware, pooled_affected) if exposed else {
            "current": firmware,
            "recommendation": "No exposed findings — no upgrade required for the analysed advisories.",
            "target": firmware,
            "rationale": "No exposed advisories.",
        }
        dev_entry = {
            "hostname": prof.get("name") or prof.get("hostname"),
            "management_ip": mgmt_ip,
            "ems_uuid": ems_uuid,
            "trust_id": trust_id,
            "model": prof.get("model"),
            "firmware": firmware,
            "advisory_count": len(adv_ids),
            "config_bytes": len(cfg_text),
            "config_error": cfg_error,
            "recommended_release": upgrade.get("target"),
            "upgrade_recommendation": upgrade.get("recommendation"),
            "upgrade_rationale": upgrade.get("rationale"),
            "exposed_findings": exposed,
        }
        if include_unmatched:
            dev_entry["unmatched_findings"] = unmatched
        else:
            dev_entry["unmatched_count"] = len(unmatched)
        devices_out.append(dev_entry)

    return {
        "summary": {
            "devices_evaluated": len(devices_out),
            "devices_with_exposure": sum(1 for d in devices_out if d.get("exposed_findings")),
            "total_exposed_findings": total_exposed,
        },
        "instructions": (
            "exposed_findings flags advisories whose subject overlaps with features "
            "enabled in latest_config (heuristic — verify with the workaround text "
            "and the actual config stanza). Set include_unmatched=True to also see "
            "advisories that apply to the device but don't match enabled features."
        ),
        "devices": devices_out,
    }

