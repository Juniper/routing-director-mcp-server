import os
import json
import logging
# Use timezone.utc (available since Python 3.2) rather than datetime.UTC,
# which only exists on Python 3.11+. The MCP package must import on 3.10 too.
from datetime import datetime, timedelta, timezone
from typing import List
from utils.lm_calls.tools.helper import validate_org_id
from utils.lm_calls.paragon.constants import (PAPI_URL, con, USE_EXTERNAL_API)

logger = logging.getLogger(__name__)


@validate_org_id
def get_custom_kpi_instantiations(org_id: str, pageNumber: int =1, limit: int =50) -> str:
    """
    Retrieves the list of custom KPI instantiations from the Routing Director.
    :param org_id: The organization ID
    :param pageNumber: The page number to start retrieving custom KPI instantiations from
    :param limit: The number of custom KPI instantiations to retrieve per call. Ideal value is 50.
    :return: JSON string containing the list of custom KPI instantiations
    """
    logger.info("get_custom_kpi_instantiations")
    params = {
        "limit": limit,
        "pageNumber": pageNumber,
    }
    if USE_EXTERNAL_API is False:
        return "Not Implemented"
    resp = con.request(method="GET", url=f"/insights/api/v1/orgs/{org_id}/instances/summary", params=params)
    return json.dumps(resp.json(), indent=2) + ". Resolve the device mac addresses to name"


@validate_org_id
def get_observability_kpis(org_id: str, mac: str) -> str:
    """
    Retrieves the list of KPIs from the Routing Director.
    :param org_id: The organization ID
    :param mac: MAC address of device without ":" or "-" (e.g., "2c6bf5660700")
    :return: JSON string containing the list of KPIs
    """
    logger.info("get_observability_kpis")
    url = f"/insights/api/v1/orgs/{org_id}/tsdb/series"
    if not mac:
        return "Please specifiy the device for which you want to retrieve the KPIs"
    mac = mac.replace(":", "").replace("-", "")
    if not org_id:
        return "Please specifiy the organization for which you want to retrieve the KPIs"
    present_time = datetime.now(timezone.utc)
    end_time =  present_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    start_time = (present_time - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = [
        {
            "device": mac,
            "topic":"[a-z].*",
            "rule":"[a-z].*",
            "field":".*",
            "start":start_time,"end":end_time
        }
    ]
    headers = {
        "Content-Type": "application/json"
    }
    if USE_EXTERNAL_API is False:
        return "Not Implemented"
    response = con.request(method="POST", url=url, headers=headers, json=body)
    resp = response.json()
    kpis = []
    kpis_unique = []
    responses = resp.get("responses", [])
    if not responses:
        return "No KPIs found for the device"
    for metric in responses[0].get("data", []):
        metric_name = metric.get("__name__", "_interested_apps")
        if metric_name.endswith("_interested_apps"):
            continue
        splits = metric_name.split("/")
        if len(splits) != 2:
            continue
        rule_splits = splits[1].split(":")
        if len(rule_splits) != 2:
            continue
        labels = []
        for label in metric:
            if label.startswith("_"):
                continue
            labels.append(label)

        kpis.append(
            {
                "topic": splits[0],
                "rule": rule_splits[0],
                "field": rule_splits[1],
                "labels": labels
            }
        )
    return json.dumps(kpis, indent=2)


@validate_org_id
def get_observability_kpi_data(org_id: str, mac: str, topic: str, rule: str, field: str, label_filters: List[str]) -> str:
    """
    Retrieves the KPI data from the Routing Director.
    :param org_id: The organization ID
    :param mac: MAC address of device without ":" or "-" (e.g., "2c6bf5660700")
    :param topic: The topic of the KPI
    :param rule: The rule of the KPI
    :param field: The field of the KPI
    :param label_filters: Filter to be applied on the data. Each element of filter is a string of format "label=value". Eg: ["label1=value1", "label2=value2"]. Ignore org_id and device_mac in filters
    :return: JSON string containing the KPI data
    """
    logger.info("get_observability_kpi_data")
    url = f"/insights/api/v1/orgs/{org_id}/tsdb/query"
    if not mac:
        return "Please specifiy the device for which you want to retrieve the KPIs"
    mac = mac.replace(":", "").replace("-", "")
    if not org_id:
        return "Please specifiy the organization for which you want to retrieve the KPIs"
    present_time = datetime.now(timezone.utc)
    end_time =  present_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    start_time = (present_time - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    where = f"time>='{start_time}' and time<='{end_time}'"
    for f in label_filters:
        label, value = f.split("=", 1)
        # label = label.replace("-", "\\-")
        value = value.replace('"', '\\"')
        where += f"and \"{label}\"='{value}'"

    body = [
        {
            "device": mac,
            "topic": topic,
            "rule": rule,
            "fields": [f"{field}"],
            "where": where,
            "groupWithout": ["_instance_id"]
        }
    ]
    headers = {
        "Content-Type": "application/json"
    }
    if USE_EXTERNAL_API is False:
        return "Not Implemented"
    logger.info("get_observability_kpi_data: %s", body)
    response = con.request(method="POST", url=url, headers=headers, json=body)
    resp = response.json()
    logger.info("get_observability_kpi_data: %s", resp)
    return json.dumps(resp, indent=2)
