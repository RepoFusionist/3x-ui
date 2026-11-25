"""Export a standalone Mihomo YAML from a privately stored Sudoku client profile."""
import argparse
import ipaddress
import json
import os
import re
from pathlib import Path

import yaml


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        profile = json.loads(args.profile.read_text(encoding="utf-8"))
        host, port = profile["server_address"].rsplit(":", 1)
        host, port = str(ipaddress.IPv4Address(host)), int(port)
        key = profile["key"]
        if (profile["mode"] != "client" or profile["transport"] != "tcp" or
                not 1 <= port <= 65535 or not re.fullmatch(r"[0-9a-fA-F]{128}", key)):
            raise ValueError("unexpected profile shape")
        if profile["httpmask"]["disable"] is not True:
            raise ValueError("expected an unmasked Sudoku listener")
        node = {
            "name": "Sudoku",
            "type": "sudoku",
            "server": host,
            "port": port,
            "key": key,
            "aead-method": profile["aead"],
            "padding-min": profile["padding_min"],
            "padding-max": profile["padding_max"],
            "table-type": profile["ascii"],
            "multiplex": profile["multiplex"],
            "httpmask": {"disable": True},
            "enable-pure-downlink": profile["enable_pure_downlink"],
        }
        document = {
            "mixed-port": 7890,
            "allow-lan": False,
            "mode": "rule",
            "proxies": [node],
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": [node["name"]]}],
            "rules": ["MATCH,PROXY"],
        }
        if args.profile.resolve().parent != args.output.resolve().parent:
            raise ValueError("output must stay beside the private source profile")
        with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                       "w", encoding="utf-8", newline="\n") as out:
            yaml.safe_dump(document, out, sort_keys=False)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "Private Mihomo export failed. No credential was printed.\n")


if __name__ == "__main__":
    main()
