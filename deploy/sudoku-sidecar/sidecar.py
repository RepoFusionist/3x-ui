#!/usr/bin/env python3
"""Provision and supervise one isolated Sudoku service beside 3x-ui."""
import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path("/opt/3x-ui-sudoku")
UNIT = "3x-ui-sudoku.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT
PANEL = "3x-ui"
SIDECAR = "3x-ui-sudoku"
UID = 19931
CHAIN = "XUI_SUDOKU_OUT"
VERSION = "v0.5.2-1"
ARCHIVE = "sudoku-linux-amd64.tar.gz"
DIGEST = "87b2330d3202ee74ac49e038249fd14dcf9952a16b25acc3cc42e6d9f7067699"
DATABASE = Path("/opt/3x-ui/db/x-ui.db")
BLOCKED = {
    "iptables": ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                 "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
                 "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"),
    "ip6tables": ("::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96",
                  "fc00::/7", "fe80::/10", "ff00::/8"),
}


def run(*args, timeout=30, check=True):
    return subprocess.run(tuple(map(str, args)), capture_output=True, check=check,
                          timeout=timeout, text=True, encoding="utf-8", errors="replace")


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs)


def panel_state():
    return docker("inspect", "-f", "{{.Id}} {{.State.Pid}} {{.State.StartedAt}}",
                  PANEL).stdout.strip()


def ns_id(pid):
    return Path(f"/proc/{pid}/ns/net").stat().st_ino


def in_ns(pid, *args, **kwargs):
    return run("nsenter", "-t", pid, "-n", *args, **kwargs)


def db():
    return sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)


def check_port(pid, port):
    if not 10001 <= port <= 10030:
        raise ValueError("port is outside the published range")
    mapping = docker("port", PANEL, f"{port}/tcp").stdout.splitlines()
    if f"0.0.0.0:{port}" not in mapping:
        raise ValueError("IPv4 TCP port is not already published")
    with db() as conn:
        if conn.execute("SELECT 1 FROM inbounds WHERE port=?", (port,)).fetchone():
            raise ValueError("port is reserved by a panel inbound")
    if in_ns(pid, "ss", "-H", "-lnt", f"sport = :{port}").stdout.strip():
        raise ValueError("port is in use in the panel network namespace")


def private_text(path, value):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600),
                   "w", encoding="utf-8") as f:
        f.write(value)


def private_json(path, value):
    private_text(path, json.dumps(value, indent=2) + "\n")


def backup():
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = ROOT / ("backup-" + stamp)
    path.mkdir(mode=0o700)
    for origin, target in (
        (Path("/opt/3x-ui/compose.yaml"), "panel.compose.yaml"),
        (Path("/opt/3x-ui-extra/compose.yaml"), "subscription.compose.yaml"),
        (Path("/opt/3x-ui-extra/config.json"), "subscription.config.json"),
    ):
        shutil.copyfile(origin, path / target)
        (path / target).chmod(0o600)
    with db() as src, sqlite3.connect(path / "x-ui.db") as dest:
        src.backup(dest)
        if dest.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise RuntimeError("database backup verification failed")
    (path / "x-ui.db").chmod(0o600)
    return path


def fetch_binary():
    artifact = ROOT / ARCHIVE
    run("curl", "-q", "--fail", "--silent", "--location", "--proto", "=https",
        "--proto-redir", "=https", "--connect-timeout", "10", "--max-time", "60",
        "--output", artifact, f"https://github.com/SUDOKU-ASCII/sudoku/releases/download/{VERSION}/{ARCHIVE}",
        timeout=65)
    with artifact.open("rb") as f:
        if hashlib.file_digest(f, "sha256").hexdigest() != DIGEST:
            raise RuntimeError("release digest mismatch")
    import tarfile
    with tarfile.open(artifact, "r:gz") as archive:
        member = archive.getmember("sudoku")
        if not member.isfile() or not 0 < member.size < 80 * 1024 * 1024:
            raise RuntimeError("unexpected release archive shape")
        with archive.extractfile(member) as src, (ROOT / "sudoku").open("xb") as dest:
            shutil.copyfileobj(src, dest)
    (ROOT / "sudoku").chmod(0o755)


def make_node(host, port):
    output = run("env", "NO_COLOR=1", "SUDOKU_LOG_LEVEL=info", ROOT / "sudoku",
                 "-keygen", timeout=15)
    keys = {}
    for label, length in (("Master Public Key", 64), ("Available Private Key", 128)):
        match = re.search(rf"{label}:\s+([0-9a-fA-F]{{{length}}})(?:\s|$)",
                          output.stdout + output.stderr)
        if not match:
            raise RuntimeError("Sudoku key generation returned an unexpected format")
        keys[label] = match[1]
    key = keys["Available Private Key"]
    common = {
        "transport": "tcp", "aead": "chacha20-poly1305", "ascii": "prefer_entropy",
        "enable_pure_downlink": True, "padding_min": 5, "padding_max": 15,
        "multiplex": "off", "httpmask": {"disable": True},
    }
    config = dict(common, mode="server", local_port=port, key=keys["Master Public Key"],
                  suspicious_action="silent", fallback_address="", external_controller="",
                  reverse={"listen": ""}, users=[{
                      "alias": "sudoku-test",
                      "key": hashlib.sha256(bytes.fromhex(key)).hexdigest()[:16],
                      "bandwidth": [20, 10],
                  }])
    private_json(ROOT / "server.json", config)
    os.chown(ROOT / "server.json", 0, UID)
    (ROOT / "server.json").chmod(0o640)
    private_json(ROOT / "client.json", dict(common, mode="client", local_port=1080,
                 key=key, server_address=f"{host}:{port}", rule_urls=["global"]))
    payload = {"h": host, "p": port, "k": key, "a": "entropy", "e": config["aead"],
               "m": 1080, "hd": True}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
    private_text(ROOT / "client-link.txt", "sudoku://" + encoded.decode().rstrip("=") + "\n")


def firewall(pid, tool, *args, **kwargs):
    return in_ns(pid, tool, "-w", "5", *args, **kwargs)


def firewall_cleanup(pid, tool):
    firewall(pid, tool, "-D", "OUTPUT", "-m", "owner", "--uid-owner", UID,
             "-j", CHAIN, check=False)
    firewall(pid, tool, "-F", CHAIN, check=False)
    firewall(pid, tool, "-X", CHAIN, check=False)


def install_firewall(pid, tool, blocked):
    firewall(pid, tool, "-N", CHAIN)
    try:
        firewall(pid, tool, "-A", CHAIN, "-m", "conntrack", "--ctstate",
                 "ESTABLISHED,RELATED", "-j", "RETURN")
        if tool == "iptables":
            firewall(pid, tool, "-A", CHAIN, "-d", "127.0.0.11", "-p", "udp",
                     "-j", "RETURN")
        for cidr in blocked:
            firewall(pid, tool, "-A", CHAIN, "-d", cidr, "-j", "REJECT")
        firewall(pid, tool, "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", UID,
                 "-j", CHAIN)
    except BaseException:
        firewall_cleanup(pid, tool)
        raise


def serve():
    before = panel_state()
    container, pid, _ = before.split()
    inode = ns_id(pid)
    port = json.loads((ROOT / "server.json").read_text())["local_port"]
    check_port(pid, port)
    installed = []
    started = False

    def stopping(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    try:
        for tool, blocked in BLOCKED.items():
            install_firewall(pid, tool, blocked)
            installed.append(tool)
        with (ROOT / "image-id").open() as f:
            image = f.read().strip()
        docker("run", "--pull=never", "--detach", "--rm", "--name", SIDECAR,
               "--network", f"container:{container}", "--read-only", "--cap-drop=ALL",
               "--security-opt", "no-new-privileges", "--user", f"{UID}:{UID}",
               "--pids-limit", 48, "--memory", "96m", "--cpus", "0.35",
               "--log-driver", "none", "--mount",
               f"type=bind,src={ROOT / 'sudoku'},dst=/sudoku,readonly", "--mount",
               f"type=bind,src={ROOT / 'server.json'},dst=/server.json,readonly",
               "--entrypoint", "/sudoku", image, "-c", "/server.json")
        started = True
        while panel_state() == before:
            if docker("inspect", "-f", "{{.State.Running}}", SIDECAR).stdout.strip() != "true":
                raise RuntimeError("Sudoku container exited")
            time.sleep(4)
    finally:
        if started:
            docker("stop", "-t", 3, SIDECAR, check=False)
        try:
            if ns_id(pid) == inode:
                for tool in reversed(installed):
                    firewall_cleanup(pid, tool)
        except FileNotFoundError:
            pass


def smoke(pid, port):
    with tempfile.TemporaryDirectory(dir=ROOT) as work:
        home = Path(work)
        conf = json.loads((ROOT / "client.json").read_text())
        conf["local_port"] = int(in_ns(pid, sys.executable, "-c",
            "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1])"
        ).stdout)
        if conf["local_port"] < 32768:
            raise RuntimeError("unexpected test port range")
        conf["server_address"] = f"127.0.0.1:{port}"
        private_json(home / "client.json", conf)
        # This client uses the real protocol and a public verification endpoint;
        # its output and credentials never go to the journal or console.
        with subprocess.Popen(("nsenter", "-t", pid, "-n", "env",
                               "SUDOKU_LOG_LEVEL=error", str(ROOT / "sudoku"),
                               "-c", str(home / "client.json")), cwd=home,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as client:
            try:
                socks = f"127.0.0.1:{conf['local_port']}"
                for _ in range(8):
                    if client.poll() is not None:
                        break
                    status = in_ns(pid, "curl", "-q", "--silent", "--fail", "--noproxy", "",
                                 "--socks5-hostname", socks, "--max-time", "6", "-o",
                                 "/dev/null", "-w", "%{http_code}",
                                 "https://www.gstatic.com/generate_204", check=False)
                    if status.returncode == 0 and status.stdout == "204":
                        return
                    time.sleep(1)
            finally:
                if client.poll() is None:
                    client.terminate()
                    try:
                        client.wait(3)
                    except subprocess.TimeoutExpired:
                        client.kill()
            raise RuntimeError("authenticated Sudoku HTTPS smoke test did not pass")


def install(host, port):
    parsed_host = ipaddress.IPv4Address(host)
    if not parsed_host.is_global or os.uname().machine != "x86_64":
        raise ValueError("expected a public IPv4 and Linux amd64")
    if ROOT.exists() or UNIT_PATH.exists() or docker("inspect", SIDECAR, check=False).returncode == 0:
        raise RuntimeError("existing Sudoku installation; refusing to overwrite")
    before = panel_state()
    pid = before.split()[1]
    check_port(pid, port)
    docker_security = docker("info", "--format", "{{json .SecurityOptions}}").stdout
    if any(option in docker_security for option in ("name=userns", "name=rootless")):
        raise RuntimeError("Docker UID mapping is incompatible with the egress rule")
    image = docker("image", "inspect", "-f", "{{.Id}}", "python:3.12-alpine").stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise RuntimeError("could not pin the local base image")
    ROOT.mkdir(mode=0o700)
    archive = backup()
    print(f"Panel backup verified: {archive}", flush=True)
    fetch_binary()
    print(f"Verified Sudoku release {VERSION}", flush=True)
    private_text(ROOT / "image-id", image + "\n")
    shutil.copyfile(__file__, ROOT / "sidecar.py")
    make_node(host, port)
    private_text(UNIT_PATH, """[Unit]
Description=Independent Sudoku listener for the published 3x-ui port
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/3x-ui-sudoku/sidecar.py serve
Restart=always
RestartSec=8
TimeoutStopSec=45
UMask=0077

[Install]
WantedBy=multi-user.target
""")
    UNIT_PATH.chmod(0o644)
    try:
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", UNIT)
        smoke(pid, port)
        isolated = docker("exec", SIDECAR, "python3", "-c",
            "import socket,sys\n"
            "try: socket.create_connection(('127.0.0.1',2053),2).close()\n"
            "except OSError: sys.exit(0)\n"
            "sys.exit(1)", check=False)
        if isolated.returncode != 0:
            raise RuntimeError("Sudoku container can reach the existing management listener")
        if panel_state() != before:
            raise RuntimeError("panel restarted during deployment")
        for origin, saved in (
            (Path("/opt/3x-ui/compose.yaml"), "panel.compose.yaml"),
            (Path("/opt/3x-ui-extra/compose.yaml"), "subscription.compose.yaml"),
            (Path("/opt/3x-ui-extra/config.json"), "subscription.config.json"),
        ):
            if origin.read_bytes() != (archive / saved).read_bytes():
                raise RuntimeError("existing configuration changed during deployment")
        status = docker("exec", "3x-ui-extra-subscription", "wget", "-q", "-O", "-",
                        "http://127.0.0.1:18082/health")
        if json.loads(status.stdout).get("ready") is not True:
            raise RuntimeError("existing subscription service is not ready")
    except BaseException:
        run("systemctl", "disable", "--now", UNIT, check=False)
        raise
    print(f"Sudoku {port}/tcp: authenticated HTTPS smoke test passed; "
          "panel uptime and subscription health verified.", flush=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("serve")
    deploy = actions.add_parser("install")
    deploy.add_argument("host")
    deploy.add_argument("port", type=int)
    args = parser.parse_args()
    if args.action == "serve":
        serve()
    else:
        install(args.host, args.port)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Don't print subprocess stderr, arguments, or configuration contents.
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        print(f"Sudoku operation stopped: {detail}", file=sys.stderr)
        sys.exit(1)
