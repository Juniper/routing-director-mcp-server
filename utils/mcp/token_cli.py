from auth_manager import (
    TokenManager,
    handle_generate_command,
    handle_list_command,
    handle_revoke_command,
    handle_show_command
)


def setup_token_subparsers(parser, required=True):
    subparsers = parser.add_subparsers(dest='command', help='Token Management Commands', required=required)

    gen_parser = subparsers.add_parser('generate', help='Generate a new API token')
    gen_parser.add_argument('-c', '--client-id', required=True, help='Unique identifier for the token')
    gen_parser.add_argument('-d', '--description', help='Description of the token usage')

    subparsers.add_parser('list', help='List all tokens')

    revoke_parser = subparsers.add_parser('revoke', help='Revoke a token')
    revoke_parser.add_argument('-c', '--client-id', required=True, help='Unique identifier (client-id) of the token to revoke')

    show_parser = subparsers.add_parser('show', help='Show a token value')
    show_parser.add_argument('-c', '--client-id', required=True, help='Unique identifier (client-id) of the token to show')


def handle_token_command(args):

    manager = TokenManager("../../.tokens")

    if args.command == 'generate':
        handle_generate_command(manager, args.client_id, args.description)
    elif args.command == 'list':
        handle_list_command(manager)
    elif args.command == 'revoke':
        handle_revoke_command(manager, args.client_id)
    elif args.command == 'show':
        handle_show_command(manager, args.client_id)

    return True


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Token Management CLI")
    setup_token_subparsers(parser)
    args = parser.parse_args()

    handle_token_command(args)


if __name__ == "__main__":
    main()
