#!/usr/bin/env python3
"""
wazuh_rule_tester.py — Wazuh Custom Rule Testing & Alert Dashboard
Author  : Mateusz Rusnak
Version : 1.0.0

PURPOSE:
    Simulate log events to test custom Wazuh rules and display
    a live terminal dashboard of triggered alerts.

USAGE:
    # Test all rules
    python3 wazuh_rule_tester.py --test-all

    # Test specific category
    python3 wazuh_rule_tester.py --category ssh

    # Watch live Wazuh alerts (requires Wazuh API access)
    python3 wazuh_rule_tester.py --live --wazuh-host 192.168.1.10

    # Generate sample logs to /var/log/rusnak_test.log
    python3 wazuh_rule_tester.py --generate-logs

REQUIREMENTS:
    pip install requests colorama
"""

import argparse
import json
import logging
import random
import sys
import time
from datetime import datetime, timezone
from typing import Optional

try:
    import requests
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False


# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("wazuh_tester")


# ── Color helpers ─────────────────────────────────────────────────────────────
def color(text: str, fg: str = "") -> str:
    if not HAS_DEPS:
        return text
    colors = {
        "red":    Fore.RED,
        "yellow": Fore.YELLOW,
        "green":  Fore.GREEN,
        "cyan":   Fore.CYAN,
        "white":  Fore.WHITE,
        "magenta": Fore.MAGENTA,
    }
    return f"{colors.get(fg, '')}{text}{Style.RESET_ALL}"


def severity_color(level: int) -> str:
    if level >= 12:
        return "red"
    if level >= 8:
        return "yellow"
    if level >= 5:
        return "cyan"
    return "white"


# ── Sample log events (simulate what Wazuh agents would forward) ──────────────
SAMPLE_EVENTS = {
    "ssh": [
        # Normal SSH failure
        {
            "rule_id": 10500,
            "level": 5,
            "description": "SSH authentication failure",
            "log": 'Dec 10 14:22:01 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 52341 ssh2',
            "category": "ssh_brute_force",
        },
        # Brute-force (simulated aggregate)
        {
            "rule_id": 10501,
            "level": 10,
            "description": "SSH Brute-Force: 5+ failed logins in 60s from 203.0.113.42",
            "log": "[AGGREGATE] 5x Failed password from 203.0.113.42 in 60s",
            "category": "ssh_brute_force",
        },
        # Success after brute-force
        {
            "rule_id": 10503,
            "level": 12,
            "description": "SSH SUCCESS after brute-force — possible credential compromise!",
            "log": 'Dec 10 14:23:45 server sshd[12346]: Accepted password for ubuntu from 203.0.113.42 port 52399 ssh2',
            "category": "ssh_brute_force",
        },
        # Root login
        {
            "rule_id": 10505,
            "level": 10,
            "description": "Direct root SSH login from 198.51.100.7",
            "log": 'Dec 10 15:01:02 server sshd[12350]: Accepted password for root from 198.51.100.7 port 54321 ssh2',
            "category": "ssh_brute_force",
        },
    ],
    "web": [
        {
            "rule_id": 10521,
            "level": 10,
            "description": "Web Brute-Force: 10+ HTTP 401 in 30s from 45.33.32.156",
            "log": '45.33.32.156 - - [10/Dec/2024:14:30:01 +0000] "POST /wp-login.php HTTP/1.1" 401 - "-" "python-requests/2.28.0"',
            "category": "web_anomaly",
        },
        {
            "rule_id": 10523,
            "level": 8,
            "description": "Known scanner detected: nikto in User-Agent from 192.168.1.55",
            "log": '192.168.1.55 - - [10/Dec/2024:14:31:00 +0000] "GET /admin/ HTTP/1.1" 404 - "-" "Nikto/2.1.6"',
            "category": "web_anomaly",
        },
        {
            "rule_id": 10524,
            "level": 10,
            "description": "SQL Injection attempt from 45.33.32.156",
            "log": "45.33.32.156 - - [10/Dec/2024:14:32:00 +0000] \"GET /api/user?id=1'+OR+1=1-- HTTP/1.1\" 200 -",
            "category": "web_anomaly",
        },
        {
            "rule_id": 10525,
            "level": 9,
            "description": "XSS attempt from 203.0.113.99",
            "log": '203.0.113.99 - - [10/Dec/2024:14:33:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 -',
            "category": "web_anomaly",
        },
    ],
    "privesc": [
        {
            "rule_id": 10541,
            "level": 8,
            "description": "sudo failure by www-data — unauthorized privilege attempt",
            "log": "Dec 10 14:40:01 server sudo: www-data : user NOT in sudoers ; TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash",
            "category": "privilege_escalation",
        },
        {
            "rule_id": 10543,
            "level": 10,
            "description": "New user account created: backdoor_user",
            "log": "Dec 10 14:41:00 server useradd[9988]: new user: name=backdoor_user, UID=1337, GID=1337",
            "category": "privilege_escalation",
        },
        {
            "rule_id": 10544,
            "level": 12,
            "description": "User backdoor_user added to sudo group — verify if authorized!",
            "log": "Dec 10 14:41:05 server usermod[9990]: add 'backdoor_user' to group 'sudo'",
            "category": "privilege_escalation",
        },
    ],
    "lateral": [
        {
            "rule_id": 10561,
            "level": 10,
            "description": "Internal network scan from 192.168.1.100",
            "log": "[AGGREGATE] 20+ TCP SYN from 192.168.1.100 to multiple IPs in 10s",
            "category": "lateral_movement",
        },
        {
            "rule_id": 10562,
            "level": 10,
            "description": "Connection to suspicious C2 port 4444 from 192.168.1.55",
            "log": "Dec 10 14:50:00 server kernel: [UFW BLOCK] SRC=192.168.1.55 DST=10.0.0.1 PROTO=TCP DPT=4444",
            "category": "lateral_movement",
        },
    ],
    "windows": [
        {
            "rule_id": 10581,
            "level": 10,
            "description": "Windows Brute-Force: 10+ logon failures from 192.168.1.77",
            "log": 'EventID=4625 Account=Administrator WorkstationName=DESKTOP-XYZ IpAddress=192.168.1.77 FailureReason=WrongPassword',
            "category": "windows_anomaly",
        },
        {
            "rule_id": 10583,
            "level": 10,
            "description": "New Windows service installed: MaliciousSvc — verify if authorized!",
            "log": 'EventID=7045 ServiceName=MaliciousSvc ServiceType=KernelDriver StartType=AutoStart AccountName=LocalSystem',
            "category": "windows_anomaly",
        },
    ],
}


# ── Alert display ─────────────────────────────────────────────────────────────
def print_header():
    header = """
╔══════════════════════════════════════════════════════════════════╗
║          WAZUH CUSTOM RULE TESTER — Mateusz Rusnak               ║
║          github.com/mateuszrusnak/wazuh-siem-rules               ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(color(header, "cyan"))


def print_alert(event: dict, index: int):
    level = event["level"]
    lvl_color = severity_color(level)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S UTC")
    badge = {
        "red":    "🔴 CRITICAL",
        "yellow": "🟡 HIGH",
        "cyan":   "🔵 MEDIUM",
        "white":  "⚪ LOW",
    }.get(lvl_color, "⚪ INFO")

    print(f"\n{'─'*70}")
    print(f"  Alert #{index:03d}  {color(badge, lvl_color)}  Level: {color(str(level), lvl_color)}")
    print(f"  Rule ID   : {color(str(event['rule_id']), 'magenta')}")
    print(f"  Time      : {timestamp}")
    print(f"  Category  : {event['category']}")
    print(f"  {color('Description:', 'white')} {color(event['description'], lvl_color)}")
    print(f"  {color('Raw log:', 'white')} {color(event['log'][:80] + ('...' if len(event['log']) > 80 else ''), 'white')}")


def print_summary(results: list):
    counts = {"CRITICAL (≥12)": 0, "HIGH (8-11)": 0, "MEDIUM (5-7)": 0, "LOW (<5)": 0}
    for e in results:
        if e["level"] >= 12:
            counts["CRITICAL (≥12)"] += 1
        elif e["level"] >= 8:
            counts["HIGH (8-11)"] += 1
        elif e["level"] >= 5:
            counts["MEDIUM (5-7)"] += 1
        else:
            counts["LOW (<5)"] += 1

    print(f"\n{'═'*70}")
    print(color("  SUMMARY — Alert Statistics", "cyan"))
    print(f"{'═'*70}")
    print(f"  Total alerts triggered : {color(str(len(results)), 'white')}")
    for label, count in counts.items():
        fg = "red" if "CRITICAL" in label else "yellow" if "HIGH" in label else "cyan"
        print(f"  {label:25s}: {color(str(count), fg)}")
    print(f"{'═'*70}\n")


# ── Live Wazuh API watcher ────────────────────────────────────────────────────
def watch_live_alerts(wazuh_host: str, token: str, rule_ids: list[int]):
    """Poll Wazuh REST API for alerts matching our custom rule IDs."""
    base_url = f"https://{wazuh_host}:55000"
    headers = {"Authorization": f"Bearer {token}"}
    rule_filter = ",".join(str(r) for r in rule_ids)

    logger.info(f"Watching live alerts from {wazuh_host} for rules: {rule_filter}")
    seen_ids: set = set()

    while True:
        try:
            resp = requests.get(
                f"{base_url}/alerts",
                headers=headers,
                params={"rule.id": rule_filter, "limit": 20, "sort": "-timestamp"},
                timeout=10,
                verify=False,  # self-signed cert common in lab setups
            )
            resp.raise_for_status()
            data = resp.json()

            for alert in data.get("data", {}).get("affected_items", []):
                alert_id = alert.get("id", "")
                if alert_id in seen_ids:
                    continue
                seen_ids.add(alert_id)

                event = {
                    "rule_id": alert.get("rule", {}).get("id"),
                    "level": alert.get("rule", {}).get("level", 0),
                    "description": alert.get("rule", {}).get("description", ""),
                    "log": alert.get("full_log", ""),
                    "category": alert.get("rule", {}).get("groups", ["unknown"])[0],
                }
                print_alert(event, len(seen_ids))

        except requests.exceptions.RequestException as e:
            logger.warning(f"API error: {e} — retrying in 5s")

        time.sleep(5)


# ── Log generator ─────────────────────────────────────────────────────────────
def generate_test_logs(output_path: str = "/tmp/rusnak_wazuh_test.log"):
    """Write sample log lines that will trigger the custom rules when read by Wazuh agent."""
    attacker_ip = "203.0.113.42"
    internal_ip = "192.168.1.100"
    now = datetime.now(timezone.utc)

    lines = []

    # SSH brute-force simulation (6 failures → triggers rule 10501)
    for i in range(6):
        t = now.strftime("%b %d %H:%M:%S")
        lines.append(f"{t} server sshd[{10000+i}]: Failed password for invalid user admin from {attacker_ip} port {50000+i} ssh2")

    # SSH success after brute
    lines.append(f"{now.strftime('%b %d %H:%M:%S')} server sshd[10006]: Accepted password for ubuntu from {attacker_ip} port 50099 ssh2")

    # Web scanner
    lines.append(f'{attacker_ip} - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /admin/ HTTP/1.1" 404 - "-" "sqlmap/1.7"')

    # SQL injection
    lines.append(f"{attacker_ip} - - [{now.strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"GET /api/search?q=1'+OR+1=1-- HTTP/1.1\" 200 42")

    # Internal scan
    for port in random.sample(range(1, 65535), 25):
        lines.append(f"{now.strftime('%b %d %H:%M:%S')} server kernel: TCP SYN from {internal_ip} to 10.0.0.1:{port}")

    # New backdoor user
    lines.append(f"{now.strftime('%b %d %H:%M:%S')} server useradd[9999]: new user: name=backdoor_user, UID=1337")
    lines.append(f"{now.strftime('%b %d %H:%M:%S')} server usermod[9998]: add 'backdoor_user' to group 'sudo'")

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    logger.info(f"Generated {len(lines)} test log lines → {output_path}")
    logger.info("Point Wazuh agent at this file via ossec.conf <localfile> to trigger rules.")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Wazuh Custom Rule Tester")
    parser.add_argument("--test-all", action="store_true", help="Run all simulated alert scenarios")
    parser.add_argument("--category", choices=["ssh", "web", "privesc", "lateral", "windows"], help="Test specific category")
    parser.add_argument("--live", action="store_true", help="Watch live Wazuh API alerts")
    parser.add_argument("--wazuh-host", default="127.0.0.1", help="Wazuh manager IP/hostname")
    parser.add_argument("--token", default="", help="Wazuh API JWT token")
    parser.add_argument("--generate-logs", action="store_true", help="Generate sample log file")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between alert displays (seconds)")
    args = parser.parse_args()

    print_header()

    if args.generate_logs:
        generate_test_logs()
        return

    if args.live:
        if not args.token:
            print(color("ERROR: --token required for live mode. Get token via:", "red"))
            print("  curl -u admin:admin -k -X POST https://WAZUH_HOST:55000/security/user/authenticate")
            sys.exit(1)
        all_rule_ids = [e["rule_id"] for cat in SAMPLE_EVENTS.values() for e in cat]
        watch_live_alerts(args.wazuh_host, args.token, all_rule_ids)
        return

    # Simulation mode
    categories = [args.category] if args.category else list(SAMPLE_EVENTS.keys())
    events_to_run = []
    for cat in categories:
        events_to_run.extend(SAMPLE_EVENTS.get(cat, []))

    print(color(f"  Running {len(events_to_run)} simulated alert(s) across {len(categories)} category/categories\n", "white"))
    time.sleep(0.5)

    for i, event in enumerate(events_to_run, 1):
        print_alert(event, i)
        time.sleep(args.delay)

    print_summary(events_to_run)


if __name__ == "__main__":
    main()
