#!/usr/bin/env python3
"""Serve the existing Sudoku link to one 3x-ui client's raw subscription."""
import argparse
import datetime
import http.server
import os
import re
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from sidecar import ROOT, DATABASE, private_text, db, docker, in_ns, panel_state, run

PORT = 18085
PATH = "/sudoku"
URL = f"http://127.0.0.1:{PORT}{PATH}"
UNIT = "3x-ui-sudoku-feed.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT
FEED_ID = 19932


def send(_signum, _frame):
    raise SystemExit(0)


def serve():
    data = sys.stdin.buffer.read(2048)
    if not re.fullmatch(rb"sudoku://[A-Za-z0-9_-]+\r?\n", data):
        raise RuntimeError("invalid private Sudoku profile")

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            pass

        def do_GET(self):
            if self.path != PATH:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    with http.server.HTTPServer(("127.0.0.1", PORT), Handler) as server:
        os.setgroups([])
        os.setgid(FEED_ID)
        os.setuid(FEED_ID)
        server.serve_forever()


def supervise():
    state = panel_state()
    pid = state.split()[1]
    signal.signal(signal.SIGTERM, send)
    signal.signal(signal.SIGINT, send)
    with subprocess.Popen(("nsenter", "-t", pid, "-n", sys.executable, __file__, "serve"),
                          stdin=subprocess.PIPE) as worker:
        try:
            worker.stdin.write((ROOT / "client-link.txt").read_bytes())
            worker.stdin.close()
            while worker.poll() is None and panel_state() == state:
                time.sleep(3)
            if worker.poll() is not None:
                raise RuntimeError("Sudoku feed exited")
        finally:
            if worker.poll() is None:
                worker.terminate()
                try:
                    worker.wait(3)
                except subprocess.TimeoutExpired:
                    worker.kill()


def owner(conn, email):
    rows = conn.execute(
        "SELECT id, enable, COALESCE(expiry_time, 0), sub_id FROM clients WHERE email=?",
        (email,)).fetchall()
    if len(rows) != 1:
        raise RuntimeError("client email did not match exactly one record")
    client, enabled, expiry, sub_id = rows[0]
    if not enabled or (expiry > 0 and expiry <= int(time.time() * 1000)) or not sub_id:
        raise RuntimeError("client has no active subscription")
    count = conn.execute("SELECT count(*) FROM clients WHERE sub_id=?", (sub_id,)).fetchone()[0]
    if count != 1:
        raise RuntimeError("subscription is shared by multiple client records")
    return client


def grant(email):
    state = panel_state()
    pid = state.split()[1]
    run("systemctl", "is-active", "3x-ui-sudoku.service")
    installed = ROOT / "grant.py"
    if UNIT_PATH.exists() or installed.exists():
        raise RuntimeError("a Sudoku feed is already installed")
    if in_ns(pid, "ss", "-H", "-lnt", f"sport = :{PORT}").stdout.strip():
        raise RuntimeError("local feed port is occupied")

    with db() as conn:
        target = owner(conn, email)
        if conn.execute("SELECT 1 FROM client_external_links WHERE value=?", (URL,)).fetchone():
            raise RuntimeError("the Sudoku feed URL is already assigned")
        date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = ROOT / f"before-sudoku-grant-{date}.db"
        with sqlite3.connect(backup) as dest:
            conn.backup(dest)
            if dest.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise RuntimeError("client database backup did not verify")
    private_text(installed, Path(__file__).read_text())
    private_text(UNIT_PATH, """[Unit]
Description=Private Sudoku subscription feed for 3x-ui
After=docker.service 3x-ui-sudoku.service
Requires=docker.service

[Service]
ExecStart=/usr/bin/python3 /opt/3x-ui-sudoku/grant.py supervise
Restart=always
RestartSec=5
TimeoutStopSec=15
UMask=0077

[Install]
WantedBy=multi-user.target
""")
    UNIT_PATH.chmod(0o644)
    try:
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", UNIT)
        # Compare the body in the process; never stream a credential to a terminal.
        for _ in range(12):
            probe = in_ns(pid, "curl", "-q", "--noproxy", "*", "-fsS",
                          "--max-time", "2", URL, check=False)
            if probe.returncode == 0 and probe.stdout.strip() == (ROOT / "client-link.txt").read_text().strip():
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("private Sudoku feed failed verification")
        bindings = in_ns(pid, "ss", "-H", "-lnt", f"sport = :{PORT}").stdout.splitlines()
        if len(bindings) != 1 or f"127.0.0.1:{PORT}" not in bindings[0]:
            raise RuntimeError("feed is not bound exclusively to IPv4 loopback")
        if panel_state() != state:
            raise RuntimeError("panel runtime changed; no client records written")
        with sqlite3.connect(DATABASE, timeout=10) as conn:
            conn.execute("BEGIN IMMEDIATE")
            if owner(conn, email) != target:
                raise RuntimeError("client record changed; refusing to assign")
            if conn.execute("SELECT 1 FROM client_external_links WHERE value=?", (URL,)).fetchone():
                raise RuntimeError("feed URL acquired an owner")
            now = time.time_ns() // 1_000_000  # Match GORM's autoCreateTime:milli column.
            conn.execute(
                "INSERT INTO client_external_links "
                "(client_id, kind, value, remark, enable, expiry_time, name_prefix, last_fetch_at, "
                "last_fetch_error, sort_index, created_at) VALUES (?, 'subscription', ?, ?, 1, 0, '', 0, '', "
                "(SELECT COALESCE(MAX(sort_index),-1)+1 FROM client_external_links WHERE client_id=?), ?)",
                (target, URL, "Sudoku", target, now))
            if conn.execute("SELECT client_id, enable FROM client_external_links WHERE value=?",
                            (URL,)).fetchall() != [(target, 1)]:
                raise RuntimeError("feed assignment failed verification")
    except BaseException:
        run("systemctl", "disable", "--now", UNIT, check=False)
        raise
    print("One active client assigned; loopback feed and database backup verified.")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("grant", "supervise", "serve"))
    parser.add_argument("email", nargs="?")
    args = parser.parse_args()
    if args.action == "grant" and args.email:
        grant(args.email)
    elif args.action == "supervise":
        supervise()
    elif args.action == "serve":
        serve()
    else:
        parser.error("an exact client email is required")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        detail = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        print(f"Sudoku feed stopped: {detail}", file=sys.stderr)
        sys.exit(1)
