"""
@copyright (c) 2024-, Juniper Networks, Inc. All rights reserved.

Tools for querying JRI (Juniper Resiliency Interface) exception data from Routing Director.

Three types of exceptions are supported:
  - Forwarding Exceptions  – packet-drop events at the forwarding plane (IPFIX).
  - OS (Kernel) Exceptions – kernel/OS-level exceptions (e.g. mbuf failures, queue drops).
  - Routing Exceptions     – route-download / KRT exceptions reported by the routing engine.

Response field reference (field names mirror the YANG path keys returned by the API):

  Common fields (all exception types):
    record_id                        – per-response unique record index
    org_id                           – organisation UUID
    device_id                        – device MAC / UUID
    exception_code                   – exception code string
    total_count                      – total matching records in the backend
    first_exception_receive_time     – Unix timestamp (seconds) of first exception in the burst
    last_exception_receive_time      – Unix timestamp (seconds) of last exception in the burst
    exception_count                  – number of times exception was reported in the time window

  Forwarding-specific core fields:
    /junos/exception-profiles/forwarding-profile/exception-owner
    /junos/exception-profiles/forwarding-profile/incident-descriptor/host-id

  Forwarding flow_information fields (present when flow_information=True):
    /junos/exception-profiles/forwarding-profile/incident-descriptor/@id
    /junos/exception-profiles/forwarding-profile/@id
    /junos/exception-profiles/forwarding-profile/forwarding-incident-descriptor/linecard-id
    /junos/exception-profiles/forwarding-profile/incident-descriptor/timestamp
    /junos/exception-profiles/forwarding-profile/forwarding-incident-descriptor/asic-index
    /junos/exception-profiles/forwarding-profile/forwarding-incident-descriptor/iif-snmp-id
    /junos/exception-profiles/forwarding-profile/forwarding-incident-descriptor/oif-snmp-id
    /junos/exception-profiles/forwarding-profile/forwarding-incident-descriptor/iif-index
    /junos/exception-profiles/forwarding-profile/forwarding-incident-descriptor/oif-index
    /junos/exception-profiles/forwarding-profile/forwarding-incident-descriptor/nh-index
    /junos/exception-profiles/forwarding-profile/forwarding-incident-descriptor/direction
    /junos/exception-profiles/forwarding-profile/forwarding-incident-descriptor/forwarding-class
    /junos/exception-profiles/forwarding-profile/frame-descriptor/src-mac-addr
    /junos/exception-profiles/forwarding-profile/frame-descriptor/dest-mac-addr
    /junos/exception-profiles/forwarding-profile/frame-descriptor/ether-type
    /junos/exception-profiles/forwarding-profile/ipv4-descriptor/protocol
    /junos/exception-profiles/forwarding-profile/ipv4-descriptor/source-addr
    /junos/exception-profiles/forwarding-profile/ipv4-descriptor/dest-addr
    /junos/exception-profiles/forwarding-profile/ipv6-descriptor/protocol
    /junos/exception-profiles/forwarding-profile/ipv6-descriptor/source-addr
    /junos/exception-profiles/forwarding-profile/ipv6-descriptor/dest-addr
    /junos/exception-profiles/forwarding-profile/mpls-ipv4-descriptor/protocol
    /junos/exception-profiles/forwarding-profile/mpls-ipv4-descriptor/source-addr
    /junos/exception-profiles/forwarding-profile/mpls-ipv4-descriptor/dest-addr
    /junos/exception-profiles/forwarding-profile/mpls-ipv4-descriptor/label

  OS-specific core fields:
    /junos/exception-profiles/os-profile/exception-owner
    /junos/exception-profiles/os-profile/incident-descriptor/host-id

  OS flow_information fields (present when flow_information=True):
    /junos/exception-profiles/os-profile/incident-descriptor/@id
    /junos/exception-profiles/os-profile/@id
    /junos/exception-profiles/os-profile/os-socket-descriptor/local-addr
    /junos/exception-profiles/os-profile/os-socket-descriptor/foreign-addr
    /junos/exception-profiles/os-profile/os-socket-descriptor/local-port
    /junos/exception-profiles/os-profile/os-socket-descriptor/foreign-port
    /junos/exception-profiles/os-profile/os-counters/isrs-low-on-mbuf-clusters
    /junos/exception-profiles/os-profile/os-counters/isrs-mbuf-alloc-failures
    /junos/exception-profiles/os-profile/os-counters/isrs-mbuf-cluster-alloc-failures
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-ether
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-ip
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-ipv6
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-arp
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-bgp
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-ospf
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-rsvp
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-isis
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-mpls
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-tcp
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-udp
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-icmp
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-icmp6
    /junos/exception-profiles/os-profile/os-counters/nw-queue-drops-ttp

  Routing-specific core fields:
    /junos/exception-profiles/routing-profile/exception-owner
    /junos/exception-profiles/routing-profile/incident-descriptor/host-id

  Routing flow_information fields (present when flow_information=True):
    /junos/exception-profiles/routing-profile/incident-descriptor/@id
    /junos/exception-profiles/routing-profile/download-path-descriptor/errno
    /junos/exception-profiles/routing-profile/download-path-descriptor/krt-status
    /junos/exception-profiles/routing-profile/download-path-descriptor/route-prefix
    /junos/exception-profiles/routing-profile/download-path-descriptor/nexthop-index
    /junos/exception-profiles/routing-profile/download-path-descriptor/krtq-op
    /junos/exception-profiles/routing-profile/download-path-descriptor/nexthop-handle
    /junos/exception-profiles/routing-profile/download-path-descriptor/sequence-number
"""

import json
import logging
import urllib.parse

from utils.lm_calls.paragon.constants import con, X_FROM
from utils.lm_calls.tools.helper import validate_org_id

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_DEFAULT_HEADERS = {"x-from": X_FROM}
_DEFAULT_PAGE_NO = 1
_DEFAULT_PER_PAGE = 10


def _jri_get(path: str, params: dict) -> str:
    """Issue a GET request to the api-server JRI endpoint and return JSON string.
    The path should be relative (e.g. /routingbot/api/v1/orgs/{org_id}/jri/...);
    con will prepend the Routing Director base URL from the config.

    Query parameters are serialised with urllib.parse.urlencode using safe='*' so
    that wildcard values ('*') are transmitted as literal '*' rather than '%2A'.
    The routingbot API only recognises the unencoded '*' as a wildcard.
    """
    try:
        query_string = urllib.parse.urlencode(
            {k: v for k, v in params.items()},
            quote_via=lambda s, safe, encoding, errors: urllib.parse.quote(str(s), safe='*'),
        )
        url_with_qs = f"{path}?{query_string}"
        resp = con.request(method="GET", url=url_with_qs, headers=_DEFAULT_HEADERS)
        resp.raise_for_status()
        return resp.text
    except Exception as exc:
        logger.error(f"Error querying {path}: {exc}")
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------


@validate_org_id
def get_jri_forwarding_exceptions(
    org_id: str,
    start_time: int,
    end_time: int,
    device_id: str = "*",
    exception_code: str = "*",
    ether_type: str = "*",
    flow_information: bool = False,
    aggregate: bool = False,
    page_no: int = _DEFAULT_PAGE_NO,
    per_page: int = _DEFAULT_PER_PAGE,
) -> str:
    """
    Retrieve JRI Forwarding (packet-drop / IPFIX) exceptions from Routing Director.

    Forwarding exceptions are generated when packets are dropped at the forwarding
    plane of a Juniper device. Each record describes a burst of drops for a
    particular flow and exception code during the requested time window.

    Key response fields:
      - record_id: sequential index within this response page
      - org_id / device_id / exception_code: identifiers
      - first_exception_receive_time / last_exception_receive_time: Unix timestamps (s)
      - exception_count: number of drops in the burst
      - total_count: total matching records in the backend
      - /junos/exception-profiles/forwarding-profile/exception-owner: subsystem that raised the exception
      - /junos/exception-profiles/forwarding-profile/incident-descriptor/host-id: host that raised the exception
      - flow_information (dict, present when flow_information=True):
          - frame/src-mac-addr, frame/dest-mac-addr, frame/ether-type
          - ipv4/source-addr, ipv4/dest-addr, ipv6/source-addr, ipv6/dest-addr
          - mpls-ipv4/label, mpls-ipv4/source-addr, mpls-ipv4/dest-addr
          - linecard-id, asic-index, iif-snmp-id, oif-snmp-id, nh-index, direction, forwarding-class

    :param org_id: Organisation UUID (mandatory).
    :param start_time: Start of the query window as a Unix timestamp in seconds (mandatory).
    :param end_time: End of the query window as a Unix timestamp in seconds (mandatory).
    :param device_id: Comma-separated device UUIDs to filter by, or "*" for all (default "*"). Use get_devices_sync to retrieve UUIDs.
    :param exception_code: Comma-separated exception codes to filter by, or "*" for all (default "*").
    :param ether_type: Packet type filter – "IPv4", "IPv6", "MPLS", or "*" for all (default "*").
    :param flow_information: When True, include per-flow packet descriptor fields (default False).
    :param aggregate: When True, deduplicate by flow hash to return unique flows only (default False).
    :param page_no: Page number for pagination (default 1).
    :param per_page: Number of records per page (default 10).
    :return: JSON string – list of forwarding exception records matching the query.
    """
    if not org_id:
        return json.dumps({"error": "org_id is required"})
    logger.info(
        f"get_jri_forwarding_exceptions org={org_id} start={start_time} end={end_time} "
        f"device_id={device_id} exception_code={exception_code} ether_type={ether_type} "
        f"flow_information={flow_information} aggregate={aggregate}"
    )
    params: dict = {
        "start_time": start_time,
        "end_time": end_time,
        "device_id": device_id,
        "exception_code": exception_code,
        "ether_type": ether_type,
        "flow_information": str(flow_information).lower(),
        "aggregate": str(aggregate).lower(),
        "page_no": page_no,
        "per_page": per_page,
    }
    path = f"/routingbot/api/v1/orgs/{org_id}/jri/forwarding-exceptions"
    return _jri_get(path, params)


@validate_org_id
def get_jri_os_exceptions(
    org_id: str,
    start_time: int,
    end_time: int,
    device_id: str = "*",
    exception_code: str = "*",
    flow_information: bool = False,
    page_no: int = _DEFAULT_PAGE_NO,
    per_page: int = _DEFAULT_PER_PAGE,
) -> str:
    """
    Retrieve JRI OS (Kernel) exceptions from Routing Director.

    OS exceptions are generated by the Junos kernel/OS layer and cover events
    such as mbuf allocation failures and per-protocol network queue drops.
    They are useful for diagnosing control-plane memory pressure or packet loss
    at the OS level.

    Key response fields:
      - record_id: sequential index within this response page
      - org_id / device_id / exception_code: identifiers
      - first_exception_receive_time / last_exception_receive_time: Unix timestamps (s)
      - exception_count: number of exceptions in the burst
      - total_count: total matching records in the backend
      - /junos/exception-profiles/os-profile/exception-owner: subsystem that raised the exception
      - /junos/exception-profiles/os-profile/incident-descriptor/host-id: host that raised the exception
      - flow_information (dict, present when flow_information=True):
          Socket descriptor:
            - os-socket-descriptor/local-addr, local-port
            - os-socket-descriptor/foreign-addr, foreign-port
          OS counters (queue drop counts per protocol):
            - isrs-low-on-mbuf-clusters, isrs-mbuf-alloc-failures, isrs-mbuf-cluster-alloc-failures
            - nw-queue-drops-ether, nw-queue-drops-ip, nw-queue-drops-ipv6
            - nw-queue-drops-arp, nw-queue-drops-bgp, nw-queue-drops-ospf
            - nw-queue-drops-rsvp, nw-queue-drops-isis, nw-queue-drops-mpls
            - nw-queue-drops-tcp, nw-queue-drops-udp, nw-queue-drops-icmp
            - nw-queue-drops-icmp6, nw-queue-drops-ttp

    :param org_id: Organisation UUID (mandatory).
    :param start_time: Start of the query window as a Unix timestamp in seconds (mandatory).
    :param end_time: End of the query window as a Unix timestamp in seconds (mandatory).
    :param device_id: Comma-separated device UUIDs to filter by, or "*" for all (default "*"). Use get_devices_sync to retrieve UUIDs.
    :param exception_code: Comma-separated exception codes to filter by, or "*" for all (default "*").
    :param flow_information: When True, include OS socket and counter detail fields (default False).
    :param page_no: Page number for pagination (default 1).
    :param per_page: Number of records per page (default 10).
    :return: JSON string – list of OS exception records matching the query.
    """
    if not org_id:
        return json.dumps({"error": "org_id is required"})
    logger.info(
        f"get_jri_os_exceptions org={org_id} start={start_time} end={end_time} "
        f"device_id={device_id} exception_code={exception_code} flow_information={flow_information}"
    )
    params: dict = {
        "start_time": start_time,
        "end_time": end_time,
        "device_id": device_id,
        "exception_code": exception_code,
        "flow_information": str(flow_information).lower(),
        "page_no": page_no,
        "per_page": per_page,
    }
    path = f"/routingbot/api/v1/orgs/{org_id}/jri/os-exceptions"
    return _jri_get(path, params)


@validate_org_id
def get_jri_routing_exceptions(
    org_id: str,
    start_time: int,
    end_time: int,
    device_id: str = "*",
    exception_code: str = "*",
    flow_information: bool = False,
    page_no: int = _DEFAULT_PAGE_NO,
    per_page: int = _DEFAULT_PER_PAGE,
) -> str:
    """
    Retrieve JRI Routing (KRT / download-path) exceptions from Routing Director.

    Routing exceptions occur when the Junos routing engine fails to install routes
    into the kernel routing table (KRT). They are critical for diagnosing route
    propagation failures and KRT errors.

    Key response fields:
      - record_id: sequential index within this response page
      - org_id / device_id / exception_code: identifiers
      - first_exception_receive_time / last_exception_receive_time: Unix timestamps (s)
      - exception_count: number of exceptions in the burst
      - total_count: total matching records in the backend
      - /junos/exception-profiles/routing-profile/exception-owner: subsystem that raised the exception
      - /junos/exception-profiles/routing-profile/incident-descriptor/host-id: host that raised the exception
      - flow_information (dict, present when flow_information=True):
          - download-path-descriptor/errno: error number describing the failure reason
          - download-path-descriptor/krt-status: KRT transaction status string
          - download-path-descriptor/route-prefix: the route prefix that failed to install
          - download-path-descriptor/nexthop-index: next-hop index
          - download-path-descriptor/krtq-op: KRT queue operation type
          - download-path-descriptor/nexthop-handle: next-hop handle
          - download-path-descriptor/sequence-number: operation sequence number

    :param org_id: Organisation UUID (mandatory).
    :param start_time: Start of the query window as a Unix timestamp in seconds (mandatory).
    :param end_time: End of the query window as a Unix timestamp in seconds (mandatory).
    :param device_id: Comma-separated device UUIDs to filter by, or "*" for all (default "*"). Use get_devices_sync to retrieve UUIDs.
    :param exception_code: Comma-separated exception codes to filter by, or "*" for all (default "*").
    :param flow_information: When True, include KRT download-path descriptor fields (default False).
    :param page_no: Page number for pagination (default 1).
    :param per_page: Number of records per page (default 10).
    :return: JSON string – list of routing exception records matching the query.
    """
    if not org_id:
        return json.dumps({"error": "org_id is required"})
    logger.info(
        f"get_jri_routing_exceptions org={org_id} start={start_time} end={end_time} "
        f"device_id={device_id} exception_code={exception_code} flow_information={flow_information}"
    )
    params: dict = {
        "start_time": start_time,
        "end_time": end_time,
        "device_id": device_id,
        "exception_code": exception_code,
        "flow_information": str(flow_information).lower(),
        "page_no": page_no,
        "per_page": per_page,
    }
    path = f"/routingbot/api/v1/orgs/{org_id}/jri/routing-exceptions"
    return _jri_get(path, params)



