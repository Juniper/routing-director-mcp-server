import copy
import logging
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
    mcp_include_tags = set()

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
                        mcp_include_tags.add(tag)

    # JRI is not a custom tool, but it is not default tool. So adding a separate check for it to add its corresponding tag if the user provides the component or using default component list which contains JRI.
    if "juniper-resiliency-interface" in components:
        mcp_include_tags.add(MCP_COMPONENTS["juniper-resiliency-interface"]["tag"])

    mcp_include_tags.add("custom-default")
    return updated_spec, mcp_include_tags
