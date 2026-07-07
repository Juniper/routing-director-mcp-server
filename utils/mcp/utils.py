import copy
import logging
import requests
from utils.mcp.constants import MCP_COMPONENTS, MCP_DEFAULT_COMPONENTS_LIST, MCP_EXTENSION_KEY, MCP_EXTENSION_LEAF_KEY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def validate_components(components: list) -> list:
    """
    Validates the user provided components, if invalid ignores the invalid components and returns only the valid ones.
    """
    valid_keys = set(MCP_COMPONENTS.keys())
    valid_components = []
    for component in components:
        if component in valid_keys:
            valid_components.append(component)
        else:
            logger.error(
                f"Invalid component `{component}` provided. Valid components are: {list(valid_keys)}, omitting it.")
    return valid_components


def get_include_tags(components: list) -> set:
    """
    Get the set of tags to be included in the MCP server based on the provided components. If no components are provided, returns the default set of tags.
    """
    if not components:
        components = MCP_DEFAULT_COMPONENTS_LIST
        logger.info("No components provided by user, using default components: %s along with custom default components", components)
    else:
        valid_components = validate_components(components)
        if not valid_components:
            logger.info("No valid components provided, using default components: %s along with custom default components", MCP_DEFAULT_COMPONENTS_LIST)
            components = MCP_DEFAULT_COMPONENTS_LIST
        else:
            components = valid_components
        logger.info("Using user-provided components for filtering: %s along with custom default components", components)

    include_tags = set()
    for component in components:
        component_info = MCP_COMPONENTS.get(component, {})
        include_tags.add(component_info.get('tag'))

    include_tags.add("custom-default")
    return include_tags


def update_openapi_specs_with_tags(openapi_spec: dict, components: list = None):
    """
    If an endpoint in the openapi spec has the MCP extension key `x-mcp-server` with leaf key `x-mcp` containing
    the component(s). Then adding the corresponding tag(s) to that endpoint and directing the MCP to only serve those with the added tags.
    If ['*'] is provided as components, no filtering is done and the original openapi spec is returned.
    Args:
        openapi_spec (dict): The original OpenAPI specification.
        components (list, optional): List of components to filter by. If None, defaults to MCP_DEFAULT_COMPONENTS_LIST.
    Returns:
        updated_spec (dict): The updated OpenAPI specification with added tags.
        mcp_include_tags (set): Set of tags corresponding to the filtered components. These tags are passed to MCP server,
                        and endpoints with these tags only are picked up by the MCP server
    """
    if components:
        if components == [ '*']:
            logging.info("Wildcard '*' detected in components, not filtering the openapi spec")
            return openapi_spec, None

        logging.info("Filtering openapi spec with user-provided components.")
        valid_components = validate_components(components)
        if not valid_components:
            logging.info("No valid components provided, using default components: %s", MCP_DEFAULT_COMPONENTS_LIST)
            components = MCP_DEFAULT_COMPONENTS_LIST
        else:
            components = valid_components
        logging.info("Filtering openapi spec with components: %s along with custom default components", components)

    else:
        logging.info("No components provided by user, using default components: %s along with custom default components", MCP_DEFAULT_COMPONENTS_LIST)
        components = MCP_DEFAULT_COMPONENTS_LIST

    updated_spec = copy.deepcopy(openapi_spec)

    for path, path_item in updated_spec.get('paths', {}).items():
        for method, operation in path_item.items():
            extension = operation.get(MCP_EXTENSION_KEY, {})
            operation_components = extension.get(MCP_EXTENSION_LEAF_KEY, [])
            for component in operation_components:
                if component in components:
                    tag = MCP_COMPONENTS.get(component, {}).get('tag')
                    if tag:
                        if tag not in updated_spec['paths'][path][method].get('tags', []):
                            updated_spec['paths'][path][method].setdefault('tags', []).append(tag)

    return updated_spec


def validate_mcp_config_file(config):
    mandatory_keys_keys = ['http_url', 'auth']
    optional_config_keys = ['openapi_spec', 'components', 'org_id']
    for key in mandatory_keys_keys:
        if key not in config:
            raise ValueError(f"Mandatory key `{key}` is missing in the MCP config file")

    valid_keys = [key for key in (mandatory_keys_keys + optional_config_keys) if key in config]
    logger.info("MCP config file validation successful. Configs used: %s", valid_keys)

    # validating the auth section in the config file
    auth_config = config.get('auth', {})
    auth_type = auth_config.get('type')
    if auth_type == 'basic':
        if auth_config.get('username', None) is None or auth_config.get('password', None) is None:
            raise ValueError("Routing Director's GUI's username and password must be provided for basic authentication in the MCP config file.")
    elif auth_type == 'token':
        if auth_config.get('token', None) is None:
            raise ValueError("Routing Director's API Token must be provided for token authentication in the MCP config file.")
    else:
        raise ValueError(f"Invalid auth type `{auth_type}` in the MCP config file. Supported types are `token` and `basic`.")

    return True


def fetch_openapi_spec_from_url(jrd_http_ip: str) -> dict:
    """
    Fetches the OpenAPI specification from the Routing Director's API documentation page.
    If fetching fails, returns an empty dictionary and logs the error.
    :param jrd_http_ip: The HTTP IP address of the Routing Director.
    :return: A dictionary representing the OpenAPI specification, or an empty dictionary if fetching fails
    """
    openapi_3_spec_url = f"{jrd_http_ip.rstrip('/')}/api/static/exports/routing-director-openapi3json.json"
    logger.info("Fetching OpenAPI spec from %s", openapi_3_spec_url)
    try:
        # coverity[ssl_verify_disabled]
        response = requests.get(openapi_3_spec_url, verify=False, timeout=30)  # nosec B501
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError as e:
        err_msg = (f"Failed to connect to {openapi_3_spec_url}. Please verify the host is reachable: {e}. \n "
                   f"Proceeding without OpenAPI spec, some of the functionalities may not work as expected.")
        logger.error(err_msg)
    except Exception as e:
        err_msg = (f"Unexpected error fetching OpenAPI spec from {openapi_3_spec_url}: {e}\n Proceeding without OpenAPI spec, "
                   f"some of the functionalities may not work as expected.")
        logger.error(err_msg)
    return {}

