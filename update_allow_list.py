"""Remove revoked IP addresses from an allow-list file.

Usage:
    python update_allow_list.py allow_list.txt 192.168.97.225 192.168.158.170

The file is expected to contain a header line (e.g. ``ip_address``)
followed by one IP address per line (any whitespace separation works).
"""
import argparse
import ipaddress


def update_allow_list(path, remove_list):
    """Remove every address in ``remove_list`` from the file at ``path``.

    Returns the list of addresses that were actually removed.
    Raises ValueError if any address in ``remove_list`` is malformed.
    """
    for ip in remove_list:
        ipaddress.ip_address(ip)

    with open(path, "r") as file:
        lines = file.read().split()
    if not lines:
        raise ValueError(f"{path} is empty")
    header, current = lines[0], lines[1:]

    to_remove = set(remove_list)
    kept = [ip for ip in current if ip not in to_remove]
    removed = [ip for ip in current if ip in to_remove]

    with open(path, "w") as file:
        file.write("\n".join([header] + kept))
    return removed


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", help="allow-list file to update")
    parser.add_argument("ips", nargs="+", help="IP addresses to revoke")
    args = parser.parse_args()
    removed = update_allow_list(args.path, args.ips)
    not_found = sorted(set(args.ips) - set(removed))
    print(f"Removed {len(removed)} address(es): {', '.join(removed) or '-'}")
    if not_found:
        print(f"Not in allow list: {', '.join(not_found)}")


if __name__ == "__main__":
    main()
