"""A simple DNS resolver inspired by "Implement DNS in a weekend" by Julia Evans."""

from __future__ import annotations

import sys

from .dns import (
    TYPE_A,
    resolve,
)


def run(args: list[str]) -> int:
    """
    Process command-line arguments and executes the DNS resolution.

    This function parses the command-line arguments to determine the domain name
    for which a DNS resolution is requested. It then calls the resolve function to
    perform the DNS query and prints the result.

    Args:
    ----
    args (list[str]): A list of command-line arguments passed to the script.
                      The first argument is expected to be the script name,
                      followed by the domain name to resolve.

    Returns:
    -------
    int: An exit code indicating the status of the operation. Returns 0 on success,
         or non-zero if an error occurs or if the arguments are invalid.
    """
    if len(args) < 2:
        print(f"Usage: {args[0]} domain_name", file=sys.stderr)
        return 1

    try:
        print(resolve(args[1], TYPE_A))
    except Exception as e:
        print(f"Error resolving domain: {e}", file=sys.stderr)
        return 2
    return 0


def main() -> None:
    """Execute the DNS resolver script."""
    sys.exit(run(sys.argv))


if __name__ == "__main__":
    main()
