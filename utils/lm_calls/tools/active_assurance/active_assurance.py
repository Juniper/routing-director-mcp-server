import json
from datetime import datetime, timezone, timedelta
from dateutil import parser
import logging
import urllib.parse
from utils.lm_calls.paragon.constants import X_FROM, PAA_URL, ALERTMANAGER_URL, METRICS_SERVICE_URL, con, USE_EXTERNAL_API
from utils.lm_calls.tools.helper import get_full_eop_host
from typing import Optional, Dict, Any, List, Tuple


MAX_PAA_RESOURCES_COUNT = 15
MAX_PAA_WORST_RESOURCES_COUNT = 5
MAX_PAA_RECENT_RESOURCES_COUNT = 5

PAA_RECENT = "recent"
PAA_WORST = "worst"
PAA_FILTER = "filter"

logger = logging.getLogger(__name__)


def _get(path, params=None):
    logger.info(f'GET {PAA_URL}{path}, params=%s', params)

    if USE_EXTERNAL_API is False:
        response = con.request(method="GET", url=f'{PAA_URL}{path}', headers={'X-From': X_FROM}, params=params)
    else:
        response = con.request(method="GET", url=path, params=params)

    return response.json()


def _get_paginated_response(path, object_name, params=None):
    result_obj_list = []
    page = 1

    new_param = {}
    if params:
        new_param = params.copy()

    while True:
        new_param['page'] = page

        logger.debug(f'paginated GET {PAA_URL}{path} with page = {page}')
        res = _get(path, params=new_param)

        page_of_objects = res.get(f'{object_name}', [])
        total_results = int(res.get('total', 0))

        if page_of_objects:
            result_obj_list.extend(page_of_objects)

        if not page_of_objects or len(result_obj_list) >= total_results:
            break

        page += 1

    return {f'{object_name}': result_obj_list}


# not used yet
def _post(path, body=None):
    logger.info(f'POST {PAA_URL}{path}, body=%s', body)

    if USE_EXTERNAL_API is False:
        response = con.request(method="POST", url=f'{PAA_URL}{path}', headers={'X-From': X_FROM}, json=body)
    else:
        response = con.request(method="POST", url=path, json=body)

    return response.json()


def _metricsservice_post(path, body=None):
    logger.info(f'POST {METRICS_SERVICE_URL}{path}, body=%s', body)

    if USE_EXTERNAL_API is False:
        response = con.request(method="POST", url=f'{METRICS_SERVICE_URL}{path}', headers={'X-From': X_FROM}, json=body)
    else:
        response = con.request(method="POST", url=path, json=body)

    return response.json()


def _metricsservice_get(path, params=None):
    logger.info(f'GET {METRICS_SERVICE_URL}{path}, params=%s', params)

    if USE_EXTERNAL_API is False:
        response = con.request(method="GET", url=f'{METRICS_SERVICE_URL}{path}', headers={'X-From': X_FROM}, params=params)
    else:
        response = con.request(method="GET", url=path, params=params)

    return response.json()


def _alertmanager_get(path, params=None):
    logger.info(f'GET {ALERTMANAGER_URL}{path}, params=%s', params)

    if USE_EXTERNAL_API is False:
        response = con.request(method="GET", url=f'{ALERTMANAGER_URL}{path}', headers={'X-From': X_FROM}, params=params)
    else:
        response = con.request(method="GET", url=path, params=params)

    return response.json()


def format_time(t: str) -> str:
    if t is None:
        return None

    try:
        target_time = parser.isoparse(t)
    except ValueError:
        logger.debug(f'Invalid time format {t}')
        return None

    current_time = datetime.now(tz=timezone.utc)
    delta = target_time - current_time
    is_future = delta.total_seconds() > 0
    abs_delta = abs(delta)

    units = [
        (2592000, "month"),
        (86400, "day"),
        (3600, "hour"),
        (60, "minute"),
        (1, "second")
    ]

    parts = []
    remaining_seconds = abs_delta.total_seconds()

    for seconds_per_unit, unit_name in units:
        if remaining_seconds >= seconds_per_unit:
            num_units = int(remaining_seconds / seconds_per_unit)

            if num_units > 0:
                parts.append(f"{num_units} {unit_name}{'s' if num_units > 1 else ''}")

            remaining_seconds %= seconds_per_unit

    # i.e. where the difference is less than a second.
    if not parts:
        return "just now"

    if len(parts) > 1:
        return f"{', '.join(parts[:-1])} and {parts[-1]}{' from now' if is_future else ' ago'}"
    else:
        return f"{parts[0]}{' from now' if is_future else ' ago'}"


def format_alert(alert):
    # TODO: Add human readable description (CCA-3266)
    # Posibly resolve based on plugin metadata, for example from `active-assurance.plugins.http.metrics.es`

    return {
        'type': alert['type'],
        'severity': alert['severity'][len('SEVERITY_'):].lower(),
        'raise_time': format_time(alert['raise_time']),
        'clear_time': format_time(alert['clear_time']),
        'test_agent_id': alert['subject'].get('test_agent_id'),
        'test_type': alert['subject'].get('plugin_name'),
        'expression': alert['subject'].get('expression')
    }


########## Test Agent ##########

def format_interface(interface):
    addresses = []
    if interface['state'] != None:
        addresses = interface['state']['ipv4s'] + interface['state']['ipv6s']

    return {
        'name': interface['name'],
        'addresses': addresses
    }


def format_test_agent(org_id, test_agent, plugin_name: str = None):
    id = test_agent['id']
    name = test_agent['metadata']['name']

    stream_count_details = get_streams_count(org_id=org_id, ta_id=id, plugin_name=plugin_name)
    stream_count = stream_count_details["number_of_streams"]
    measurments_with_plugin = stream_count_details["num_of_measurements_with_specific_plugin"]
    stream_per_plugin = stream_count_details["stream_count_per_plugin"]

    if plugin_name and measurments_with_plugin == 0:
        return {'number_of_measurements_with_plugin': 0}

    # Get 5 most severe alerts and total alert count for this Test Agent
    # alerts = _alertmanager_get(f'/alert-manager/api/v1/orgs/{org_id}/alerts', params={
    #     'subject[test_agent_id]': test_agent['id'],
    #     'limit': 5,
    # })
    alert_count = {}
    try:
        alert_count = _alertmanager_get(f'/alert-manager/api/v1/orgs/{org_id}/alerts/count',
                                        params={
                                            'subject[test_agent_id]': test_agent['id'],
                                            'group_by_severity': 'true',
                                        })
        if alert_count['groups']:
            alert_count = alert_count['groups'][0]['severity']
        else:
            alert_count = {}
    except Exception:
        logger.error(f'Error in getting alerts on test agent')
        pass
    interfaces = _get(
        f'/active-assurance/api/v2/orgs/{org_id}/test_agents/{test_agent["id"]}/interfaces')

    site = None
    if 'site' in test_agent:
        site = test_agent['site']

    device = None
    if 'device' in test_agent:
        device = test_agent['device']

    # For TYPE_APPLICATION and TYPE_APPLIANCE the online status is based on this attribute
    ta_online = test_agent['online']

    ta_device_online = False
    if device:
        ta_device_online = device['online']

    ta_type = test_agent['types']
    if ta_type:
        if "TYPE_DEVICE" in ta_type:
            if "TYPE_APPLICATION" in ta_type:
                ta_online = ta_online and ta_device_online
            else:
                ta_online = ta_device_online

    formatted_test_agent_info = {
        'id': id,
        'name': name,
        'site': site,
        'online': ta_online,
        'stream_count': stream_count,
        'last_connect_time': format_time(test_agent['last_connect_time']),
        'last_disconnect_time': format_time(test_agent['last_disconnect_time']),
        'interfaces': [format_interface(interface) for interface in interfaces['test_agent_interfaces']],
        'appliance': test_agent['appliance'],
        'types': test_agent['types'],
        'device': device,
        'active_alert_count': alert_count,
    }

    if plugin_name:
        formatted_test_agent_info["number_of_measurements_with_plugin"] = measurments_with_plugin
    else:
        formatted_test_agent_info["measurements_per_plugin"] = stream_per_plugin

    formatted_test_agent_info[
        'details_url'] = f'{get_full_eop_host()}/test-agents/test-agents?details_active_tab=overview&id={id}&name={name}'

    return formatted_test_agent_info


def get_streams_count(org_id, ta_id: str, plugin_name: str = None, ):
    """
    List all the streams for a test agent. Also check the count of measurement by plugin_name

    Args:
        ta_id (str): the test-agent Id.
        plugin_name (str): the plugin name (optional).

    Returns:
        A map with count of Streams running for the test_agent and number of measurements with specific plugin
    """

    body = {
        'filter': f'measurement.test_agent.id="{ta_id}"'
    }

    res = _metricsservice_get(f'/active-assurance/api/v2/orgs/{org_id}/streams', params=body)

    num_meas_with_plugin = 0
    total_number_of_streams = 0
    stream_count_per_plugin_dict: dict[str, int] = {}
    for stream_info in res["streams"]:
        meas_info = stream_info["measurement"]
        if not meas_info or meas_info["status"] != 'STATUS_RUNNING':
            continue

        plugin_info = meas_info["plugin"]
        if not plugin_info:
            continue

        curr_plugin = plugin_info["name"]

        total_number_of_streams += 1
        stream_count_per_plugin_dict[curr_plugin] = stream_count_per_plugin_dict.get(curr_plugin, 0) + 1

        if plugin_name and curr_plugin == plugin_name:
            num_meas_with_plugin += 1

    stream_per_plugin = [
        {"plugin_name": name, "number_of_measurements": count}
        for name, count in stream_count_per_plugin_dict.items()
    ]

    return {"number_of_streams": total_number_of_streams,
            "num_of_measurements_with_specific_plugin": num_meas_with_plugin,
            "stream_count_per_plugin": stream_per_plugin}


def format_task(org_id, task):
    # Get 5 most severe alerts and total alert count for this Test Agent
    alerts = _alertmanager_get(f'/alert-manager/api/v1/orgs/{org_id}/alerts', params={
        'subject[task_id]': task['id'],
        'limit': 5,
    })

    alert_count = _alertmanager_get(f'/alert-manager/api/v1/orgs/{org_id}/alerts/count', params={
        'subject[task_id]': task['id'],
        'group_by_severity': 'true',
    })

    active_alert_count = 0
    if alert_count['groups']:
        active_alert_count = alert_count['groups'][0]['severity']

    return {
        'task_id': task['id'],
        'task_name': task['metadata']['name'],
        'plugin': task['plugin'],
        'config': task['config'],
        'create_time': task['create_time'],
        'active_alert_count': active_alert_count,
        'active_alerts': [format_alert(alert) for alert in alerts['results']],
    }


def active_assurance_list_test_agents_sync(
        org_id: str,
        action: str,
        id: str,
        name: str,
        site_name: str,
        site_addr: str,
        device_mac: str,
        device_name: str,
        plugin_name: str,
        aggregation_action: str,
) -> str:
    """
    Get information about Test Agents. Use `action="worst"` when asking about Test Agents with alerts.
    Use `action=\"filter\"` when ranking/counting Test Agents based on measurements,
    or filtering on `id`, `name`, `site`, `device_mac`, `plugin_name`

    Args:
        org_id (str): The ID of the organization.
        action (str): The action to list worst Test Agents or filter Test Agents (e.g. "worst", "filter")
        id (str): The ID of the Test Agent (optional). Default is None.
        name (str): The name of the Test Agent (optional). Default is None.
        site_name (str): The name of the site where the Test Agent is located (optional). Default is None.
        site_addr (str): The address of the site where the Test Agent is located (optional). Default is None.
        device_mac (str): MAC address of the device associated with test agent (optional). Default is None.
        device_name (str): Name of the device associated with test agent (optional). Default is None.
        plugin_name (str): Name of the plugin to get the number of measurements running with that plugin (optional). Default is None.
        aggregation_action(str): values `max` or `min` for number of measurements. Only valid with action="filter". (optional) Default is None.

    Returns:
        str: The Test Agent information in JSON format.
    """

    if plugin_name or id or name or device_mac or site_name or site_addr:
        action = PAA_FILTER

    if plugin_name:
        plugin_details = active_assurance_list_plugin_schema_sync(
            org_id=org_id, plugin_name="", brief=False)
        if not plugin_details:
            return json.dumps({
                'error': 'ValueError',
                'message': f"Fetching plugins to verify plugin name `{plugin_name}` failed"
            })

        plugin_details = json.loads(plugin_details)
        valid_titles = [p["title"] for p in plugin_details]

        if plugin_name not in valid_titles:
            return json.dumps({
                'error': 'ValueError',
                'message': f"`{plugin_name}` is not a valid plugin. Use any of the following `{valid_titles}`"
            })

    test_agents = ""
    if action == PAA_WORST:
        test_agents = list_worst_test_agents(org_id=org_id)
    elif action == PAA_FILTER:
        test_agents = list_test_agents(org_id, id, name, site_name, site_addr, device_mac, device_name, plugin_name,
                                       aggregation_action)

    return test_agents


def list_worst_test_agents(org_id) -> str:
    """
    Get a list of upto 5 Test Agents with the most major or critical Alerts.

    Returns:
        str: A list of Test Agents in JSON format.
    """

    params = {
        'group_by': 'subject.test_agent_id',
        'group_limit': MAX_PAA_WORST_RESOURCES_COUNT + 1,  # The result might also include the "empty" value
        'severity': 'SEVERITY_MAJOR',
        # 'group_by_severity': 'true',
    }

    # Get the 5 Test Agents with most Alerts
    alert_count = _alertmanager_get(f'/alert-manager/api/v1/orgs/{org_id}/alerts/count',
                                    params=params)

    # Get the Test Agent IDs, skip the "empty" group
    ids = [group["name"] for group in alert_count['groups'] if group["name"] != ''][:MAX_PAA_WORST_RESOURCES_COUNT]
    if not ids:
        return []

    res = _get(f'/active-assurance/api/v2/orgs/{org_id}/test_agents', params={
        'filter': ' OR '.join(f'id="{id}"' for id in ids),
    })

    test_agents = [format_test_agent(org_id, ta) for ta in res.get("test_agents", [])]

    if not test_agents:
        return json.dumps({
            "error": "NotFound",
            "message": "No test agents found with major alert."
        })

    return json.dumps(test_agents)


def list_test_agents(org_id: str, id: str = None, name: str = None, site_name: str = None, site_addr: str = None,
                     device_mac: str = None, device_name: str = None, plugin_name: str = None,
                     aggregation_action: str = None) -> str:
    """
    Get information about a single test agent or multiple Test Agents. Either `id`, `name` or `site` or
       `device MAC` or `device name` has to be specified to filter the results.

    Args:
        org_id (str): The ID of the organization. It is a mandatory parameter.
        id (str): The ID of the Test Agent (optional).
        name (str): The name of the Test Agent (optional).
        site_name (str): The name of the site where the Test Agent is located (optional).
        site_addr (str): The address of the site where the Test Agent is located (optional).
        device_mac (str): MAC address of the device associated with test agent (optional).
        device_name (str): Name of the device associated with test agent (optional).
        plugin_name (str): Name of the plugin. (optional).
        aggregation_action(str): test_agents with max/min number of measurements (optional).

    Returns:
        str: The Test Agent information in JSON format.
    """

    params = {}

    if id:
        params['filter'] = f'id="{id}"'
    if name:
        params['filter'] = f'metadata.name="{name}"'
    if site_name:
        params['filter'] = f'site.name="{site_name}"'
    if site_addr:
        params['filter'] = f'site.address="*{site_addr}*"'
    if device_mac:
        params['filter'] = f'device.mac="{device_mac}"'
    if device_name:
        params['filter'] = f'device.name="{device_name}"'
    if not any([id, name, site_name, site_addr, device_mac, device_name, plugin_name, aggregation_action]):
        # With no filter limit the maximum number of results upto MAX_PAA_RESOURCES_COUNT
        params['limit'] = MAX_PAA_RESOURCES_COUNT

    try:
        res: Dict[str, Any] = _get_paginated_response(f'/active-assurance/api/v2/orgs/{org_id}/test_agents',
                                                      object_name='test_agents',
                                                      params=params)

        raw_agents: List[Dict[str, Any]] = res.get('test_agents', [])
        if not raw_agents:
            return json.dumps({'error': 'NotFound', 'message': 'No Test Agents found for the given criteria.'})

        if plugin_name:
            test_agents = [
                agent for item in raw_agents
                if (agent := format_test_agent(org_id, item, plugin_name=plugin_name))
                   and agent.get('number_of_measurements_with_plugin', 0) > 0
            ]
        else:
            test_agents = [format_test_agent(org_id, item) for item in raw_agents]

        if aggregation_action:
            test_agents = test_agent_aggregated_with_measurements(
                test_agent_details=test_agents,
                aggregation_action=aggregation_action,
                plugin_name=plugin_name if plugin_name else None
            )

        if not test_agents:
            filters = []

            if params and "filter" in params:
                filters.append(f"filter={params['filter']}")
            if plugin_name:
                filters.append(f"plugin_name={plugin_name}")
            if aggregation_action:
                filters.append(f"aggregation_action={aggregation_action}")

            filter_str = ", ".join(filters) if filters else "no filters"

            return json.dumps({
                "error": "NotFound",
                "message": f"No test agents found with {filter_str}."
            })

        return json.dumps(test_agents)

    except ValueError as e:
        return json.dumps({'error': 'ValueError', 'message': str(e)})  # Return error as json.

    except Exception as e:
        return json.dumps({'error': 'Exception', 'message': str(e)})  # Return other errors as json.


def test_agent_aggregated_with_measurements(test_agent_details: list[any], aggregation_action: str,
                                            plugin_name: str = None):
    key = 'number_of_measurements_with_plugin' if plugin_name else 'stream_count'
    measurements = [item[key] for item in test_agent_details]

    if not measurements:
        return test_agent_details

    if aggregation_action == 'max':
        max_value = max(measurements)
        return [item for item in test_agent_details if item[key] == max_value]
    elif aggregation_action == 'min':
        min_value = min(measurements)
        return [item for item in test_agent_details if item[key] == min_value]

    return test_agent_details


########## Monitor ##########


def format_monitor(org_id, monitor):
    # Get 5 most severe alerts and total alert count for this Test Agent
    # alerts = _alertmanager_get(f'/alert-manager/api/v1/orgs/{org_id}/alerts', params={
    #     'subject[monitor_id]': monitor['id'],
    #     'limit': 5,
    # })

    alert_count = _alertmanager_get(f'/alert-manager/api/v1/orgs/{org_id}/alerts/count', params={
        'subject[monitor_id]': monitor['id'],
        'group_by_severity': 'true',
    })
    if alert_count['groups']:
        alert_count = alert_count['groups'][0]['severity']
    else:
        alert_count = {}

    id = monitor['id']
    name = monitor['metadata']['name']
    return {
        'id': id,
        'name': name,
        'status': monitor['status_message'],
        'active_alert_count': alert_count,
        'tasks': [format_task(org_id, task) for task in monitor['tasks']],
        'details_url': f'{get_full_eop_host()}/monitors/monitors?id={id}&mode=monitor_detail&name={name}'
    }


def active_assurance_list_monitors_sync(org_id: str, action: str, id: str, name: str,
                                         only_failed: bool) -> str:
    """
    Get information about a single monitor or multiple Monitors. If the action is "recent" it lists recent monitors.
    If the action is "worst" it lists worst monitors. If action is "filter" it lists monitors based on
    id or name. only_failed is relevant only when query type is "recent".

    Args:
        org_id (str): The ID of the organization. It is a mandatory parameter.
        action (str): The type of action to perform (e.g., "recent", "worst", "filter")
        id (str): The ID of the Monitor (optional). Default is None.
        name (str): The name of the Monitor (optional). Default is None.
        only_failed (bool): Only return failed monitors. Default is False.

    Returns:
        str: The Monitor information in JSON format.
    """

    if action == PAA_FILTER:
        if not (id or name):
            return json.dumps({'error': 'ValueError', 'message': "Either `id` or `name` has to be specified"})

    monitors = ""
    if action == PAA_RECENT:
        monitors = list_recent_monitors(org_id, only_failed)
    elif action == PAA_WORST:
        monitors = list_worst_monitors(org_id=org_id)
    elif action == PAA_FILTER:
        monitors = list_monitors(org_id, id, name)

    return monitors


def list_monitors(org_id: str, id: str = None, name: str = None) -> str:
    """
    Get information about a single monitor or multiple Monitors. Either `id` or `name` has to be specified.
    It filters monitor based on id or name.

    Args:
        org_id (str): The ID of the organization. It is a mandatory parameter.
        id (str): The ID of the Monitor (optional).
        name (str): The name of the Monitor (optional).

    Returns:
        str: The Monitor information in JSON format.
    """

    params = {
        'limit': MAX_PAA_RESOURCES_COUNT
    }
    if id:
        params['filter'] = f'id="{id}"'
    elif name:
        params['filter'] = f'metadata.name="{name}"'
    else:
        return json.dumps({'error': 'ValueError', 'message': "Either `id` or `name` has to be specified"})

    res = _get(f'/active-assurance/api/v2/orgs/{org_id}/monitors', params=params)
    if int(res['total']) == 0:
        return json.dumps({'error': 'ValueError', 'message': 'Monitor not found'})

    monitors = []
    for monitor in res['monitors']:
        monitors.append(format_monitor(org_id, monitor)),

    if not monitors:
        return json.dumps({
            "error": "NotFound",
            "message": f"No monitors found with {params['filter']}."
        })

    return json.dumps(monitors)


def list_worst_monitors(org_id) -> str:
    """Get a list of upto 5 Monitors with the most major or critical Alerts.

    Args:
        org_id (str): The ID of the organization. It is a mandatory parameter.
    Returns:
        str: A list of Monitors in JSON format.
    """

    # Get the 5 Monitors with most Alerts
    alert_count = _alertmanager_get(f'/alert-manager/api/v1/orgs/{org_id}/alerts/count', params={
        'group_by': 'subject.monitor_id',
        'group_limit': MAX_PAA_WORST_RESOURCES_COUNT + 1,  # The result might also include the "empty" value
        'severity': 'SEVERITY_MAJOR',
        # 'group_by_severity': 'true',
    })

    notFoundMsg = json.dumps({
        "error": "NotFound",
        "message": f"No monitors found with major active alerts."
    })

    # Get the Monitor IDs, skip the "empty" group
    ids = [group["name"] for group in alert_count['groups'] if group["name"] != ''][:MAX_PAA_WORST_RESOURCES_COUNT]
    if not ids:
        return notFoundMsg

    res = _get(f'/active-assurance/api/v2/orgs/{org_id}/monitors', params={
        'filter': ' OR '.join(f'id="{id}"' for id in ids),
    })
    monitors = []
    for monitor in res['monitors']:
        monitors.append(format_monitor(org_id, monitor)),

    if not monitors:
        return notFoundMsg

    return json.dumps(monitors)


def list_recent_monitors(org_id, only_failed: bool = False) -> str:
    """
    Get a list of upto 5 most recent Monitors.

    Args:
        org_id (str): The ID of the organization. It is a mandatory parameter.
        only_failed (bool): Only return failed tests.

    Returns:
        str: A list of Monitors in JSON format.
    """

    params = {
        'order_by': 'create_time desc',
        'limit': MAX_PAA_RECENT_RESOURCES_COUNT,
    }
    if only_failed:
        params['filter'] = 'status="STATUS_FAILED"'

    res = _get(f'/active-assurance/api/v2/orgs/{org_id}/monitors', params=params)
    monitors = []
    for monitor in res['monitors']:
        monitors.append(format_monitor(org_id, monitor)),

    if not monitors:
        return json.dumps({
            "error": "NotFound",
            "message": f"No monitors found."
        })

    return json.dumps(monitors)


########## Test ##########


def format_test(org_id, test):
    exec_id = test['id']
    test_id = test['test']['id']
    name = test['test']['metadata']['name']
    return {
        'test_id': test_id,
        'execution_id': exec_id,
        'name': name,
        'status': test['status'][len('STATUS_'):].lower(),
        'execution_start_time': format_time(test['execution_start_time']),
        'execution_end_time': format_time(test['execution_end_time']),
        'tasks': [format_task(org_id, task) for step in test['test']['test_steps'] for task in step.get('tasks', [])],
        'details_url': f'{get_full_eop_host()}/tests/tests?execution_id={exec_id}&id={test_id}&mode=test_detail&name={name}'
    }


def active_assurance_list_tests_sync(org_id: str, action: str, id: str, name: str,
                                      only_failed: bool) -> str:
    """
    Get information about a single test or multiple tests. If the action is "recent" it lists recent tests.
    If the action is "worst" it lists worst tests. If action is "filter" it lists tests
    filtered on id or name. only_failed is relevant only when query type is "recent".

    Args:
        org_id (str): The ID of the organization. It is a mandatory parameter.
        action (str): The type of action to perform (e.g., "recent", "worst", "filter")
        id (str): The ID of the Test (optional). Default is None.
        name (str): The name of the Test (optional). Default is None.
        only_failed (bool): Only return failed tests. Default is False.

    Returns:
        str: The Test information in JSON format.
    """

    if action == PAA_FILTER:
        if not (id or name):
            raise ValueError("Either `id` or `name` has to be specified")
    tests = ""
    if action == PAA_RECENT:
        tests = list_recent_tests(org_id, only_failed)
    elif action == PAA_WORST:
        tests = list_worst_tests(org_id)
    elif action == PAA_FILTER:
        tests = list_tests(org_id, id, name)

    return tests


def list_tests(org_id: str, id: str = None, name: str = None) -> str:
    """
    Get information about a single test or multiple Tests. Either `id` or `name` has to be specified.

    Args:
        org_id (str): The ID of the organization. It is a mandatory parameter.
        id (str): The ID of the Test (optional).
        name (str): The name of the Test (optional).

    Returns:
        str: The Test information in JSON format.
    """

    params = {
        'limit': MAX_PAA_RESOURCES_COUNT
    }

    if id:
        params['filter'] = f'id="{id}"'
    elif name:
        params['filter'] = f'test.metadata.name="{name}"'
    else:
        raise ValueError("Either `id` or `name` has to be specified")

    res = _get(f'/active-assurance/api/v2/orgs/{org_id}/tests/-/executions', params=params)
    if int(res['total']) == 0:
        raise ValueError('Test not found')

    tests = []
    for test in res['test_executions']:
        tests.append(format_test(org_id, test)),

    if not tests:
        return json.dumps({
            "error": "NotFound",
            "message": f"No tests found with {params['filter']}."
        })

    return json.dumps(tests)


def list_worst_tests(org_id) -> str:
    """
    Get a list of upto 5 Tests with the most major or critical Alerts.

    Args:
        org_id (str): The ID of the organization. It is a mandatory parameter.
    Returns:
        str: A list of Tests in JSON format.
    """

    # Get the 5 Tests with most Alerts
    alert_count = _alertmanager_get(f'/alert-manager/api/v1/orgs/{org_id}/alerts/count', params={
        'group_by': 'subject.test_id',
        'group_limit': MAX_PAA_WORST_RESOURCES_COUNT + 1,  # The result might also include the "empty" value
        'severity': 'SEVERITY_MAJOR',
        # 'group_by_severity': 'true',
    })

    notFoundMsg = json.dumps({
        "error": "NotFound",
        "message": f"No tests found with major active alerts."
    })

    # Get the Test IDs, skip the "empty" group
    ids = [group["name"] for group in alert_count['groups'] if group["name"] != ''][:MAX_PAA_WORST_RESOURCES_COUNT]
    if not ids:
        return notFoundMsg

    res = _get(f'/active-assurance/api/v2/orgs/{org_id}/tests/-/executions', params={
        'filter': ' OR '.join(f'id="{id}"' for id in ids),
    })
    tests = []
    for test in res['test_executions']:
        tests.append(format_test(org_id, test)),

    if not tests:
        return notFoundMsg

    return json.dumps(tests)


def list_recent_tests(org_id: str, only_failed: bool = False) -> str:
    """
    Get a list of upto 5 most recent Tests.

    Args:
        org_id (str): The ID of the organization. It is a mandatory parameter.
        only_failed (bool): Only return failed tests.

    Returns:
        str: A list of Tests in JSON format.
    """

    params = {
        'order_by': 'execution_start_time desc',
        'limit': MAX_PAA_RECENT_RESOURCES_COUNT,
    }
    if only_failed:
        params['filter'] = 'status="STATUS_FAILED"'

    res = _get(f'/active-assurance/api/v2/orgs/{org_id}/tests/-/executions', params=params)
    tests = []
    for test in res['test_executions']:
        tests.append(format_test(org_id, test)),

    if not tests:
        return json.dumps({
            "error": "NotFound",
            "message": f"No tests found."
        })

    return json.dumps(tests)


########## Plugin ##########


def format_plugin(plugin, brief=False):
    plugin_name = plugin['metadata']['name']
    plugin_display_name = plugin['metadata']['display_name']
    metrics = plugin['schema']['metrics']
    metrics_container = []
    for metric in metrics:
        metric_name = metric['name']
        metric_description = metric['description']
        metric_unit = metric.get('unit', 'N/A')
        metric_display_name = metric['label']
        metric_container = {
            "metric_name": metric_name,
            "description": f'{metric_display_name} : {metric_description}'
        }
        if not brief:
            metric_container["unit"] = metric_unit
        metrics_container.append(metric_container)

    if brief:
        return metrics_container

    return {
        "plugin_name": plugin_name,
        "plugin_display_name": plugin_display_name,
        "enabled": plugin['enabled'],
        "metrics": metrics_container,
    }


def active_assurance_list_plugin_schema_sync(org_id: str, plugin_name: str, brief: bool) -> str:
    """
    Get details of single plugin schema or for all plugin schemas if no plugin name specified.
    Plugin schema for a plugin includes metrics definitions reported by the plugin.

    Args:
        org_id (str): The ID of the organization
        plugin_name (str): Name of plugin
        brief (bool): True if being called from another function call `active_assurance_list_measurements_with_metrics`

    Returns:
        str: The plugin schema containing metric definitions reported in JSON format.
    """

    params = None
    try:
        res = _get(f'/active-assurance/api/v2/orgs/{org_id}/plugins', params=params)
    except Exception:
        logger.error(f'Error in getting plugin schema')
        return ''

    if not plugin_name or plugin_name == '*' or plugin_name == 'all':
        brief = False
        plugins = []
        for plugin in res['plugins']:
            info = {}
            metadata = plugin.get("metadata", {})
            info["display_name"] = metadata["display_name"]
            info["title"] = metadata["name"]
            info["description"] = metadata["description"]
            plugins.append(info)
        return json.dumps(plugins)
    else:
        plugin_name = plugin_name.lower()
        for plugin in res['plugins']:
            plugin_entry = None
            if plugin['metadata']['name'].lower() == plugin_name or plugin['metadata'][
                'display_name'].lower() == plugin_name:
                plugin_entry = plugin
                break

        return json.dumps(format_plugin(plugin_entry, brief=brief))


########## Measurements ##########


def format_metrics(org_id: str, metrics_from_measurement, metric_name: str,
                   start_time: str = None, end_time: str = None, aggregation_action: str = None,
                   caches: dict[str:any] = None):
    observed_time = metrics_from_measurement.get('observed_time')
    measurement_id = metrics_from_measurement.get('measurement_id')
    value = metrics_from_measurement.get('int_val') or metrics_from_measurement.get('float_val')

    if value is None:
        return None

    if aggregation_action == 'avg' and not measurement_id:
        # for avg case and per_measurement false case, there won't be any measurement_id in the aggregation API response
        return {metric_name: value, }

    res = {
        'measurement ID': measurement_id,
        metric_name: value,
    }

    if start_time and end_time:
        body = {
            'filter': f'measurement.id="{measurement_id}"'
        }

        stream_details = None
        if caches:
            stream_details = caches['streams'].get(measurement_id, None)
        if not stream_details:
            stream_res = _metricsservice_get(f'/active-assurance/api/v2/orgs/{org_id}/streams', params=body)
            stream_details = stream_res['streams'][0]
        stream_id = stream_details['id']

        enc_start = urllib.parse.quote(start_time)
        enc_end = urllib.parse.quote(end_time)

        if aggregation_action in ('max', 'min') and observed_time:
            obs_dt = datetime.strptime(observed_time, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
            new_start_dt = obs_dt - timedelta(minutes=30)
            new_end_dt = obs_dt + timedelta(minutes=30)

            now = datetime.now(tz=timezone.utc)
            time_difference = now - new_start_dt
            three_days = timedelta(days=3)

            if time_difference > three_days:
                new_start_dt = obs_dt - timedelta(hours=12)
                new_end_dt = obs_dt + timedelta(hours=12)

            updated_start_time_str = new_start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            updated_end_time_str = new_end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

            enc_start = urllib.parse.quote(updated_start_time_str)
            enc_end = urllib.parse.quote(updated_end_time_str)

        res[
            'details_url'] = f'{get_full_eop_host()}/measurements/measurements?end_time={enc_end}&id={measurement_id}&start_time={enc_start}&stream_ids={stream_id}'

    if observed_time:
        res['observed time'] = observed_time

    return res


def list_streams_for_test_or_monitor(org_id: str, type: str, id: str, plugin_name: str):
    """
    List all the streams for a test or monitor.

    Args:
        org_id (str): The ID of the organization. The mandatory parameter.
        measurement_type (str): The type "monitor" or "test".
        id (str): the monitor Id or test Id.
        plugin_name (str): Name of the plugin.

    Returns:
        A list of Streams for the monitor or test.
    """

    conditions = [
        f'measurement.plugin.name="{plugin_name}"'
    ]

    if type == 'monitor':
        conditions.append(f'config.metadata.tags.__sys__monitor_id="{id}"')
    elif type == 'test':
        conditions.append(f'config.metadata.tags.__sys__test_execution_id="{id}"')
    else:
        return None

    filter = ' AND '.join(conditions)

    body = {
        'filter': filter
    }

    res = _metricsservice_get(f'/active-assurance/api/v2/orgs/{org_id}/streams', params=body)

    return res


def get_aggregated_metrics(org_id: str,
                           measurements,
                           start_time: str,
                           end_time: str,
                           metric: str,
                           function: str = None,
                           per_measurement: bool = None,
                           ):
    """
    Retrieves aggregated metrics for a given list of measurements within a specified time range.

    Args:
        org_id: The ID of the organization. The mandatory parameter.
        measurements: A set of measurement IDs to retrieve metrics for.
        start_time: The starting timestamp for the metric aggregation in ISO 8601 format (e.g., "2025-04-22T00:00:00Z").
        end_time: The ending timestamp for the metric aggregation in ISO 8601 format (e.g., "2025-04-23T00:00:00Z").
        metric: The name of the metric to aggregate (e.g., "rtt", "loss").
        function: An optional aggregation function to apply. Supported values depend on the metrics service (e.g., "max", "min", "avg",). Defaults to None, implying avg.
        per_measurement: An optional boolean indicating whether to calculate and return aggregated metrics for each individual measurement. Defaults to None.

    Returns:
        A dictionary containing the aggregated metric results.
    """

    body = {
        "measurement_ids": list(measurements),
        "start_time": start_time,
        "end_time": end_time,
        "metric": metric,
    }

    if function:
        body['function'] = function

    if per_measurement is not None:
        body['per_measurement'] = per_measurement

    logger.debug(
        f'get_aggregated_metrics: /active-assurance/api/v2/orgs/{org_id}/streams/metrics:aggregate {body}')
    res = _metricsservice_post(f'/active-assurance/api/v2/orgs/{org_id}/streams/metrics:aggregate',
                               body=body)
    return res


def list_measurements(org_id: str, plugin_name: str, test_agent_id: str, measurement_type: str = None,
                      caches: dict[str:any] = None) -> dict[str, any]:
    """
    Get a list of Measurements filtered by plugin_name, test_agent_id.

    Args:
        org_id (str): The ID of the organization.
        plugin_name (str): Filter measurements by Plugin Name.
        test_agent_id (str): Filter measurements by Test Agent Id.
        measurement_type (str): Filter measurements by measurement type. It can be "test" or "monitor". If not mentioned both are listed. (optional)

    Returns:
        str: A map of diffferent Measurements and its details with Measurement IDs as the keys.
    """

    if plugin_name and test_agent_id:
        conditions = [
            f'test_agent.id="{test_agent_id}"',
            f'plugin.name="{plugin_name}"'
        ]
        filter = ' AND '.join(conditions)
    elif plugin_name:
        filter = f'plugin.name="{plugin_name}"'
    elif test_agent_id:
        filter = f'test_agent.id="{test_agent_id}"'

    params = {
        'order_by': 'create_time desc',
        'filter': filter
    }

    res = _get_paginated_response(f'/active-assurance/api/v2/orgs/{org_id}/measurements',
                                  object_name='measurements',
                                  params=params)
    raw_meas: List[Dict[str, Any]] = res.get('measurements', [])
    measurements = {}
    for meas in raw_meas:
        if measurement_type == 'test':
            if 'metadata' in meas and 'tags' in meas['metadata'] and '__sys__test_execution_id' in \
                    meas['metadata']['tags']:
                measurements[meas['id']] = format_measurement(org_id=org_id, measurement_info=meas, caches=caches)
        elif measurement_type == 'monitor':
            if 'metadata' in meas and 'tags' in meas['metadata'] and '__sys__monitor_id' in meas['metadata'][
                'tags']:
                measurements[meas['id']] = format_measurement(org_id=org_id, measurement_info=meas, caches=caches)
        else:
            measurements[meas['id']] = format_measurement(org_id=org_id, measurement_info=meas, caches=caches)

    return measurements


def format_measurement(org_id, measurement_info, caches: dict[str:any] = None):
    """
    Get a map of single measurement details.

    Args:
        org_id (str): The ID of the organization.
        measurement_info (str): details of a single measurement as fetched from API.

    Returns:
        str: A map of Measurement with keys being its attributes.
    """
    if not measurement_info:
        return None

    res = {}
    stream_name = ''

    ta_info = measurement_info['test_agent']
    metadata = measurement_info['metadata']

    bind_iface = ta_info.get('bind_iface', None)
    bind_address = ta_info.get('bind_address', None)
    on_device = ta_info.get('on_device', None)
    meta_name = metadata.get('name', None)

    ta_id = ta_info['id']
    test_agent = None
    if caches:
        test_agent = caches['test_agents'].get(ta_id, None)
    if not test_agent:
        test_agents_str = list_test_agents(org_id=org_id, id=ta_id)
        test_agent_list = json.loads(test_agents_str)
        handleErrorFromFunctionCalls(test_agent_list)
        test_agent = test_agent_list[0]

    device_info = test_agent.get('device', None)
    site_info = test_agent.get('site', None)
    if device_info:
        model = device_info.get('model', None)
        dev_name = device_info.get('name', None)
        if model:
            res['model'] = model
        if dev_name:
            stream_name = dev_name
    if site_info and site_info.get('name', None):
        res['site'] = site_info['name']

    if bind_iface:
        stream_name = stream_name + f' {bind_iface}'

    if bind_address:
        stream_name = stream_name + f' {bind_address}'

    if on_device:
        stream_name = stream_name + ' (on device)'

    if meta_name:
        stream_name = stream_name + f' {meta_name}'

    res['stream_name'] = stream_name

    monitor_id = metadata['tags'].get('__sys__monitor_id', None)
    test_exec_id = metadata['tags'].get('__sys__test_execution_id', None)
    measurement_type = 'monitor' if monitor_id else ('test' if test_exec_id else None)

    if measurement_type == 'test':
        test_exec_info = None
        if caches:
            test_exec_info = caches['tests'].get(test_exec_id, None)
        if not test_exec_info:
            test_exec_data = list_tests(org_id=org_id, id=test_exec_id)
            test_exec_list = json.loads(test_exec_data)
            handleErrorFromFunctionCalls(test_exec_list)
            test_exec_info = test_exec_list[0]

        if test_exec_info.get('execution_id') == test_exec_id:
            res['test name'] = test_exec_info['name']
    elif measurement_type == 'monitor':
        monitor_info = None
        if caches:
            monitor_info = caches['monitors'].get(monitor_id, None)
        if not monitor_info:
            monitor_data = list_monitors(org_id=org_id, id=monitor_id)
            monitor_info_list = json.loads(monitor_data)
            handleErrorFromFunctionCalls(monitor_info_list)
            monitor_info = monitor_info_list[0]

        if monitor_info.get('id') == monitor_id:
            res['monitor name'] = monitor_info['name']

    return res


def active_assurance_list_measurements_with_metrics_sync(org_id: str,
                                                         metric_name: str,
                                                         plugin_name: str,
                                                         aggregation_action: str,
                                                         start_time: str,
                                                         end_time: str,
                                                         site: str,
                                                         test_agent_name: str,
                                                         monitor_test_name: str,
                                                         measurement_type: str,
                                                         per_measurement: bool) -> str:
    """
    Find and summarize measurements along with the maximum, minimum, or average metric values filtered based on the type `test` or `monitor`
    or the name of the "site" or "monitor" or "test". For `max` and `min` aggregation_action, the time of such observation is also provided.

    Args:
        org_id (str): The ID of the organization.
        metric_name (str): To be retrieved from `metric_name` from function call `active_assurance_list_plugin_schema(org_id=org_id, plugin_name=plugin_name, brief=True)`
        plugin_name (str): Name of the plugin.
        aggregation_action (str): The aggregation function to apply (`max`, `min`, or `avg`). (optional) Default is None.
        start_time (str): The starting time in `YYYY-MM-DDTHH:MM:SSZ` format. Interpret from prompt with reference to current time `active_assurance_get_current_time`. Default is None.
        end_time (str): The ending time in `YYYY-MM-DDTHH:MM:SSZ` format. Interpret from prompt with reference to current time `active_assurance_get_current_time`. Default is None.
        site (str): The name of the site. (optional) Default is None.
        test_agent_name (str): The name of the test `agent`. (optional) Default is None.
        monitor_test_name (str): The name of the `monitor` or `test`. If provided the `measurement_type` field will be changed accordingly (optional) Default is None.
        measurement_type (str): Filter measurements by measurement type. It can be `test` or `monitor`. Needed if `monitor_test_name` field is present. (optional) Default is None.
        per_measurement (bool): True if aggregated result is needed per measurement and False if the result is required across the measurements.

    Returns:
        str: A list of Metrics info with measurement details, monitor/test name, stream name, site, model and its URL in JSON format.
    """

    caches: dict[str:any] = {}
    caches['measurements'] = {}
    caches['monitors'] = {}
    caches['tests'] = {}
    caches['test_agents'] = {}
    caches['streams'] = {}
    metrics = []

    if not plugin_name:
        return json.dumps({'error': 'ValueError',
                           'message': "Name of the `plugin_name` has to be specified"})

    plugin_details = active_assurance_list_plugin_schema_sync(org_id=org_id, plugin_name=plugin_name, brief=True)
    plugin_details = json.loads(plugin_details)
    if not any(details["metric_name"] == metric_name for details in plugin_details):
        return json.dumps({'error': 'ValueError',
                           'message': f"`{metric_name}` is not a metric for plugin `{plugin_name}`, Use any of the following `{plugin_details}`"})

    stream_measuremets = []
    test_agent_ids = []

    now = datetime.now(tz=timezone.utc)

    if not aggregation_action or aggregation_action not in ('max', 'min', 'avg'):
        aggregation_action = 'avg'

    if not end_time:
        end_time = now.strftime('%Y-%m-%dT%H:%M:%SZ')

    if not start_time:
        seventy_one_hours_ago = now - timedelta(hours=71)
        start_time = seventy_one_hours_ago.strftime('%Y-%m-%dT%H:%M:%SZ')

    if monitor_test_name and measurement_type:
        task_ids = []
        executions = None
        if measurement_type == 'monitor':
            monitors_res = list_monitors(org_id=org_id, name=monitor_test_name)
            executions = json.loads(monitors_res)
            if executions:
                handleErrorFromFunctionCalls(executions)

                plugins_use_map = {}
                for exec in executions:
                    for task in exec['tasks']:
                        plugin_for_exec = task['plugin']['name']
                        plugins_use_map[plugin_for_exec] = plugins_use_map.get(plugin_for_exec, 0) + 1
                        if plugin_name == plugin_for_exec:
                            task_ids.append(exec['id'])
                            caches['monitors'][exec['id']] = exec

                if plugin_name not in plugins_use_map.keys():
                    return json.dumps({'error': 'ValueError',
                                       'message': f"For monitor `{monitor_test_name}` only plugins found are {plugins_use_map.keys()}"})
        elif measurement_type == 'test':
            tests_res = list_tests(org_id=org_id, name=monitor_test_name)
            executions = json.loads(tests_res)
            if executions:
                handleErrorFromFunctionCalls(executions)

                plugins_use_map = {}
                for exec in executions:
                    for task in exec.get('tasks', []):
                        plugin_for_exec = task['plugin']['name']
                        plugins_use_map[plugin_for_exec] = plugins_use_map.get(plugin_for_exec, 0) + 1
                        if plugin_name == plugin_for_exec:
                            task_ids.append(exec['execution_id'])
                            caches['tests'][exec['execution_id']] = exec

                if plugin_name not in plugins_use_map.keys():
                    return json.dumps({'error': 'ValueError',
                                       'message': f"For test `{monitor_test_name}` only plugins found are {plugins_use_map.keys()}"})

        if task_ids:
            for task_id in task_ids:
                stream_details = list_streams_for_test_or_monitor(org_id=org_id, type=measurement_type, id=task_id,
                                                                  plugin_name=plugin_name)
                for stream in stream_details['streams']:
                    stream_meas = stream.get('measurement')
                    formatted_meas = format_measurement(org_id=org_id, measurement_info=stream_meas, caches=caches)
                    stream_measuremets.append(stream_meas['id'])
                    caches['measurements'][stream_meas['id']] = formatted_meas
                    caches['streams'][stream_meas['id']] = stream

        if not stream_measuremets:
            return json.dumps({'error': 'ValueError',
                               'message': f'No streams found for the {measurement_type} {monitor_test_name}'})

    elif site or test_agent_name:
        if site:
            test_agents_str = list_test_agents(org_id=org_id, site_name=site)
        else:
            test_agents_str = list_test_agents(org_id=org_id, name=test_agent_name)

        test_agents = json.loads(test_agents_str)
        handleErrorFromFunctionCalls(test_agents)

        for test_agent in test_agents:
            test_agent_ids.append(test_agent['id'])
            caches['test_agents'][test_agent['id']] = test_agent

        if len(test_agent_ids) == 0:
            return json.dumps({'error': 'ValueError',
                               'message': f'No test agents found for the {site if site else test_agent_name}'})

    measurement_ids = []
    if len(test_agent_ids) > 0:
        # Case when site or test_agent_name is propmted
        for test_agent_id in test_agent_ids:
            measurement_details = list_measurements(org_id=org_id, plugin_name=plugin_name, test_agent_id=test_agent_id,
                                                    measurement_type=measurement_type, caches=caches)
            if len(measurement_details) > 0:
                current_meas_ids = list(measurement_details)
                measurement_ids.extend(current_meas_ids)
                caches['measurements'].update(measurement_details)
    elif len(stream_measuremets) > 0:
        # Case when monitor or test name is provided
        measurement_ids = stream_measuremets
    else:
        measurement_details = list_measurements(org_id=org_id, plugin_name=plugin_name, test_agent_id=None,
                                                measurement_type=measurement_type, caches=None)
        measurement_ids = list(measurement_details)
        caches['measurements'] = measurement_details

    res = get_aggregated_metrics(org_id=org_id, measurements=set(measurement_ids),
                                 start_time=start_time, end_time=end_time,
                                 metric=metric_name, function=aggregation_action, per_measurement=per_measurement)

    for meas in res['metrics']:
        formatted_metrics = format_metrics(org_id=org_id, metrics_from_measurement=meas, metric_name=metric_name,
                                           start_time=start_time, end_time=end_time,
                                           aggregation_action=aggregation_action, caches=caches)

        if not (per_measurement == False and aggregation_action == 'avg'):
            # for avg case and per_measurement false case, there won't be any measurement_id in the aggregation API response
            measurement_id = formatted_metrics.get('measurement ID', None)
            if measurement_id:
                meas_for_metric = caches['measurements'].get(measurement_id, None)
                if meas_for_metric:
                    formatted_metrics.update(meas_for_metric)

        if formatted_metrics:
            metrics.append(formatted_metrics)

    if not metrics:
        return json.dumps({
            "error": "NotFound",
            "message": f"No metrics found with {metric_name} on plugin {plugin_name} with the provided filters."
        })

    return f"```json\n{json.dumps(metrics, indent=2)}\n```"


def handleErrorFromFunctionCalls(jsonDumpObj: Any):
    if jsonDumpObj:
        if isinstance(jsonDumpObj, dict) and 'error' in jsonDumpObj:
            message = jsonDumpObj.get('message', '')
            raise ValueError(f"{jsonDumpObj['error']}: {message}")


def active_assurance_get_current_time_sync() -> str:
    """
    Get current UTC time

    Args:

    Returns:
        str: Current UTC time in json format
    """

    now = datetime.now(tz=timezone.utc)
    return json.dumps(now.strftime('%Y-%m-%dT%H:%M:%SZ'))
