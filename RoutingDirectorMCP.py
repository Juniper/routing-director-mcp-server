import os
import sys
import argparse

from utils.mcp.server import create_mcp_server
import logging

def main():
    parser = argparse.ArgumentParser(description="Routing Directory MCP Server")
    parser.add_argument('-H', '--host', default="127.0.0.1", type=str, help='Routing Directory MCP Server host')
    parser.add_argument('-p', '--port', default=30030, type=int, help='Routing Directory MCP Server port')
    parser.add_argument('-t', '--transport', default="streamable-http", type=str, help='Routing Directory MCP Server transport')
    parser.add_argument('-c', '--config', type=str, help='Routing Directory MCP Server config file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument("--ssl-key", help="Path to SSL key file")
    parser.add_argument("--ssl-cert", help="Path to SSL certificate file")

    args = parser.parse_args()

    os.environ['USE_EXTERNAL_API'] = "true"

    log_level = os.getenv("LOG_LEVEL", "ERROR").upper()

    if args.verbose:
        os.environ['MCP_VERBOSE'] = "true"
        logging.basicConfig(level=getattr(logging, log_level, logging.ERROR))

    logger = logging.getLogger(__name__)

    try:
        create_mcp_server(args)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        # Handle expected configuration/startup errors gracefully without
        # dumping a stack trace. Show a clear message and guidance.
        logger.error(f"Error: {exc}\n", file=sys.stderr)
        # Only show the config-file guidance when the config file wasn't provided
        # (the missing-config check lives in utils/mcp/server.py).
        if args.config is None:
            logger.error(
                "Please provide a valid configuration file using the -c/--config option.\n"
                "Example:\n"
                "  python RoutingDirectorMCP.py --config config.json\n",
                file=sys.stderr,
            )
            parser.print_help(sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.error("\nShutting down Routing Director MCP Server.", file=sys.stderr)
        sys.exit(0)

if __name__ == "__main__":
    main()
