# Independent Sudoku listener

This opt-in companion runs the standalone Sudoku protocol alongside 3x-ui. It uses an unused TCP port that the existing 3x-ui container already publishes. It does not add a panel protocol option or modify existing panel records, routes, subscriptions, Compose files, or Lightsail firewall rules. Install only one instance per host.

Prerequisites: Linux amd64, Python 3.11+, systemd, Docker with iptables, a local `python:3.12-alpine` image, and the 3x-ui/sidecar paths checked by the installer. Use a port from 10001–10030 that has a public IPv4 TCP Docker mapping and is not reserved by an enabled or disabled inbound. Reserve the chosen port so it is not selected for future 3x-ui inbounds.

Copy the installer to the host over your normal trusted SSH connection, then run:

```bash
sudo python3 sidecar.py install PUBLIC_IPV4 UNUSED_PUBLISHED_TCP_PORT
```

The installer checks a pinned [Sudoku release](https://github.com/SUDOKU-ASCII/sudoku/releases/tag/v0.5.2-1) against its SHA-256 digest. It verifies a consistent SQLite backup, creates one authorized client, and starts the resource-limited companion without replacing 3x-ui. Egress rules in the shared network namespace apply to the companion UID and block new connections to the panel, private networks, and cloud metadata. The service follows 3x-ui when the main container is later replaced.

The root-only `/opt/3x-ui-sudoku/client.json` and `/opt/3x-ui-sudoku/client-link.txt` are two ways to import the same node into a compatible client. Transfer them privately; they contain the same client credential. The deployment test uses a temporary local protocol client to fetch an HTTPS verification URL. External client connectivity still depends on the existing cloud firewall.

Rollback: `sudo systemctl disable --now 3x-ui-sudoku.service`. The service stops its container and removes its egress rules; no rollback of the panel database is required. The installation directory and protected backups are retained.

## Account-specific Sudoku over WSS

For a deployment with Caddy on port 443, use a separate loopback-only Mihomo Sudoku listener for every account that you want to enable. Generate a distinct key and WebSocket path for each listener. Add an exact WebSocket route in Caddy that forwards only that path to its listener. Leave the existing site and other routes in place.

Match each account to its existing SOCKS outbound when preparing the listener configuration. In Mihomo, bind the listener name to that one outbound with an `IN-NAME` rule, and end the rules with `MATCH,REJECT`. Accounts without an unambiguous outbound should not receive a node. The 3x-ui patch renders the node; it does not provision Caddy paths or choose the LSP automatically.

In 3x-ui, add the corresponding `sudoku://` share link as an enabled external **link** for that client, with the remark `Sudoku`. Use the public WSS hostname and port 443 in the link. The existing modern Clash subscription will include that node on its next refresh. Keep its key and live configuration private. The loopback **subscription** used by the standalone pilot is independent of these per-user links.

The ordinary Clash subscription also offers `自动选择` using the subscriber's existing primary nodes. It does not require an imported spare subscription, and Sudoku stays available for manual selection.
