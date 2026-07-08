import json
import os
import asyncio
import logging
from typing import Optional

from fastmcp import FastMCP

from utils.mcp.auth_manager import TokenManager
from utils.mcp.utils import update_openapi_specs_with_tags, get_include_tags, fetch_openapi_spec_from_url, validate_mcp_config_file
from utils.mcp.constants import SERVER_NAME

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


mcp: Optional[FastMCP] = None
mcp_config: str = ""


def load_config(config_path: str) -> dict:
    if not config_path:
        raise ValueError("Config file path is required")
    try:
        with open(config_path) as f:
            return json.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to load config from {config_path}: {e}")

def _load_mcp_plugins() -> None:
    # Import all MCP modules so they can register with FastMCP
    import utils.mcp.ems  # noqa: F401
    import utils.mcp.fh  # noqa: F401
    import utils.mcp.insights  # noqa: F401
    import utils.mcp.network_optimization  # noqa: F401
    import utils.mcp.trust  # noqa: F401
    import utils.mcp.active_assurance  # noqa: F401
    import utils.mcp.routing_intelligence  # noqa: F401


def create_mcp_server(args):
    global mcp_config
    global mcp

    if args.config is None:
        raise ValueError("Routing Directory MCP Server config file is required")

    mcp_config = args.config
    config = load_config(mcp_config)
    validate_mcp_config_file(config)

    # Setting necessary environment variables for the MCP server based on the config file.
    os.environ['EOP_HOST'] = config.get('http_url')
    os.environ['MCP_CONFIG'] = mcp_config

    # Initialize a process-wide *sync* Routing Director client and store it in the request context.
    from utils.lm_calls.connection.client_connection import SyncHttpxClient, set_con
    set_con(SyncHttpxClient(config_path=mcp_config))

    token_manager = TokenManager()

    verifier = None
    if args.transport != 'stdio':
        if token_manager.tokens_file_exists():
            logger.info("Tokens file found. Authentication enabled.")
            verifier = token_manager.get_verifier()
        else:
            logger.warning("No tokens file found. Authentication DISABLED.")
            verifier = None
    else:
        logger.info("Using stdio transport - authentication bypassed")

    openapi_spec_path = config.get('openapi_spec')

    if openapi_spec_path:
        with open(openapi_spec_path) as fh:
            spec = json.load(fh)
    else:
        spec = fetch_openapi_spec_from_url(config.get('http_url'))

    if not spec:
         mcp = FastMCP(name=SERVER_NAME, log_level="DEBUG", auth=verifier)
    else:
        components = config.get('components', [])
        include_tags = get_include_tags(components)

        # If user provides a valid component list in the config.json, filtering the openapi spec for the specified
        # components, else filtering the openapi spec with the default component list . Only the endpoints with the
        # openapi extension `x-mcp-server` will be included for  mcp, not all the endpoints in the openapi spec.
        updated_spec = update_openapi_specs_with_tags(openapi_spec=spec, components=components)

        from utils.lm_calls.connection.client_connection import create_routing_director_async_client
        # The tool calls generated from the openapi spec doesn't work with sync httpx client, so using
        # async httpx client for the mcp server when openapi spec is provided. The async client is only
        # used for the tool calls, the mcp server itself will run in sync mode.
        async_con = create_routing_director_async_client()

        # Validate the configured Routing Director credentials before starting the
        # server. If authentication fails (e.g. incorrect UI credentials in the
        # config file), abort startup instead of bringing up a server that cannot
        # service any tool calls.
        if async_con is not None:
            authenticated = asyncio.run(async_con.verify_authentication())
            if not authenticated:
                raise RuntimeError(
                    "Authentication with Routing Director failed. Please verify the "
                    "credentials in the config file. MCP server will not start."
                )

        mcp = FastMCP.from_openapi(name=SERVER_NAME, openapi_spec=updated_spec,
                                   client=async_con, auth=verifier, include_tags=include_tags)

    _load_mcp_plugins()
    if config.get("org_id", None) is not None:
        mcp.prompt(f"Organization ID or org id is {config.get('org_id')}")

    # Prepare SSL config if provided
    uvicorn_config = None
    if getattr(args, 'ssl_key', None) and getattr(args, 'ssl_cert', None):
        if os.path.exists(args.ssl_key) and os.path.exists(args.ssl_cert):
            logger.info(f"SSL enabled. Cert: {args.ssl_cert}, Key: {args.ssl_key}")
            uvicorn_config = {
                "ssl_keyfile": args.ssl_key,
                "ssl_certfile": args.ssl_cert
            }
        else:
            logger.error(f"SSL files not found: {args.ssl_key} or {args.ssl_cert}")

    if args.transport == 'stdio':
        mcp.run(transport=args.transport)
    elif args.transport == 'streamable-http':
        mcp.run(host=args.host, port=args.port, transport=args.transport, uvicorn_config=uvicorn_config)
    else:
        mcp.run(host=args.host, port=args.port, transport=args.transport)
