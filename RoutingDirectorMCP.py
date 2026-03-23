import os
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
    create_mcp_server(args)

if __name__ == "__main__":
    main()
