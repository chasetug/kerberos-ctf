#!/usr/bin/env python3

import json
import secrets
import sys

# ===== COLORS =====
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"


KDC = "A"

CLIENTS = {
    "B": "bob",
    "C": "charlie",
}

SERVICE_HOSTS = {
    "D": "mysql",
    "E": "http",
}

SERVICES = {v: k for k, v in SERVICE_HOSTS.items()}

FLAG = "FLAG{valid_ticket_chain}"

BANNER = f"""
{BOLD}Mini Kerberos CTF{RESET}

Hosts:
  A = KDC / Domain Controller
  B = bob
  C = charlie
  D = mysql server
  E = http server

Goal:
  Submit the 3 client-side packets in the correct order:
    1. AUTH_REQ
    2. SERVICE_REQ
    3. APP_REQ

The KDC automatically generates AUTH_REP and SERVICE_REP.

Commands:
  help   - show packet formats
  reset  - reset the current session
  state  - show current session state
  quit   - exit
"""


def new_session() -> dict:
    return {
        "expected_step": 1,
        "client": None,
        "user": None,
        "service": None,
        "service_host": None,
        "tgt": None,
        "service_ticket": None,
        "complete": False,
    }


session = new_session()


def reset_session() -> None:
    global session
    session = new_session()
    print(f"{YELLOW}[RESET]{RESET} Session reset.")
    print(f"{CYAN}Expected next step:{RESET} AUTH_REQ")


def fail(msg: str) -> None:
    print(f"{RED}[ALERT]{RESET} {msg}")
    reset_session()


def make_tgt(user: str) -> str:
    return f"TGT_{user.upper()}_{secrets.token_hex(3).upper()}"


def make_service_ticket(user: str, service: str) -> str:
    return f"ST_{user.upper()}_{service.upper()}_{secrets.token_hex(3).upper()}"


def pretty(obj: dict) -> None:
    print(json.dumps(obj, indent=2))


def print_help() -> None:
    print(
        f"""
Packet formats:

1) AUTH_REQ
{{
  "src": "B",
  "dst": "A",
  "type": "AUTH_REQ",
  "user": "bob"
}}

2) SERVICE_REQ
{{
  "src": "B",
  "dst": "A",
  "type": "SERVICE_REQ",
  "service": "mysql",
  "tgt": "TGT_BOB_ABC123"
}}

3) APP_REQ
{{
  "src": "B",
  "dst": "D",
  "type": "APP_REQ",
  "service": "mysql",
  "service_ticket": "ST_BOB_MYSQL_DEF456"
}}

Notes:
- Clients:
    B -> bob
    C -> charlie

- Services:
    D -> mysql
    E -> http

- The KDC will generate the TGT and service ticket for you.
- Reuse the exact values the KDC gives you.
- If you make a mistake, the session resets.
"""
    )


def print_state() -> None:
    safe_view = {
        "expected_step": session["expected_step"],
        "client": session["client"],
        "user": session["user"],
        "service": session["service"],
        "service_host": session["service_host"],
        "tgt": session["tgt"],
        "service_ticket": session["service_ticket"],
        "complete": session["complete"],
    }
    pretty(safe_view)


def validate_auth_req(packet: dict) -> None:
    src = packet.get("src")
    dst = packet.get("dst")
    user = packet.get("user")

    if packet.get("type") != "AUTH_REQ":
        fail("Expected AUTH_REQ as the first packet.")
        return

    if src not in CLIENTS:
        fail("AUTH_REQ must come from a valid client (B or C).")
        return

    if dst != KDC:
        fail("AUTH_REQ must be sent to A.")
        return

    expected_user = CLIENTS[src]
    if user != expected_user:
        fail(f"AUTH_REQ user mismatch. Expected '{expected_user}' for client '{src}'.")
        return

    session["client"] = src
    session["user"] = expected_user
    session["tgt"] = make_tgt(expected_user)
    session["expected_step"] = 3

    print(f"{GREEN}[OK]{RESET} {src} -> {dst} AUTH_REQ accepted")
    print(f"{BLUE}Auto-generated response:{RESET}")
    pretty(
        {
            "src": "A",
            "dst": src,
            "type": "AUTH_REP",
            "tgt": session["tgt"],
        }
    )
    print(f"{CYAN}Expected next step:{RESET} SERVICE_REQ")


def validate_service_req(packet: dict) -> None:
    src = packet.get("src")
    dst = packet.get("dst")
    service = packet.get("service")
    tgt = packet.get("tgt")

    if packet.get("type") != "SERVICE_REQ":
        fail("Expected SERVICE_REQ as the next packet.")
        return

    if src != session["client"]:
        fail("SERVICE_REQ must come from the same client that requested the TGT.")
        return

    if dst != KDC:
        fail("SERVICE_REQ must be sent to A.")
        return

    if service not in SERVICES:
        valid_services = ", ".join(sorted(SERVICES.keys()))
        fail(f"SERVICE_REQ must request a valid service ({valid_services}).")
        return

    if tgt != session["tgt"]:
        fail("SERVICE_REQ used an invalid or modified TGT.")
        return

    session["service"] = service
    session["service_host"] = SERVICES[service]
    session["service_ticket"] = make_service_ticket(session["user"], service)
    session["expected_step"] = 5

    print(f"{GREEN}[OK]{RESET} {src} -> {dst} SERVICE_REQ accepted")
    print(f"{BLUE}Auto-generated response:{RESET}")
    pretty(
        {
            "src": "A",
            "dst": src,
            "type": "SERVICE_REP",
            "service": service,
            "service_ticket": session["service_ticket"],
        }
    )
    print(f"{CYAN}Expected next step:{RESET} APP_REQ")


def validate_app_req(packet: dict) -> None:
    src = packet.get("src")
    dst = packet.get("dst")
    service = packet.get("service")
    service_ticket = packet.get("service_ticket")

    if packet.get("type") != "APP_REQ":
        fail("Expected APP_REQ as the final packet.")
        return

    if src != session["client"]:
        fail("APP_REQ must come from the same authenticated client.")
        return

    if dst != session["service_host"]:
        fail("APP_REQ must be sent to the correct host for the requested service.")
        return

    if service != session["service"]:
        fail("APP_REQ service does not match the service requested earlier.")
        return

    expected_host = SERVICES.get(service)
    if expected_host != dst:
        fail(f"APP_REQ host/service mismatch. Service '{service}' belongs on host '{expected_host}'.")
        return

    if service_ticket != session["service_ticket"]:
        fail("APP_REQ used an invalid or modified service ticket.")
        return

    session["complete"] = True

    print(f"{GREEN}[OK]{RESET} {src} -> {dst} APP_REQ accepted")
    print(f"{GREEN}{BOLD}ACCESS GRANTED{RESET}")
    pretty(
        {
            "src": dst,
            "dst": src,
            "type": "ACCESS_GRANTED",
            "flag": FLAG,
        }
    )
    print(f"{GREEN}{BOLD}[SUCCESS]{RESET} Challenge solved.")
    print("Type 'reset' to play again or 'quit' to exit.")


def handle_packet(packet: dict) -> None:
    if session["complete"]:
        print(f"{CYAN}[INFO]{RESET} Challenge already solved. Type 'reset' to play again.")
        return

    if not isinstance(packet, dict):
        fail("Packet must be a JSON object.")
        return

    if session["expected_step"] == 1:
        validate_auth_req(packet)
    elif session["expected_step"] == 3:
        validate_service_req(packet)
    elif session["expected_step"] == 5:
        validate_app_req(packet)
    else:
        fail("Internal error: invalid session step.")


def repl() -> None:
    print(BANNER.strip())
    print_help()
    print()
    reset_session()

    while True:
        try:
            raw = input(f"{BOLD}packet>{RESET} ").strip()
        except EOFError:
            print("\nExiting.")
            return
        except KeyboardInterrupt:
            print("\nExiting.")
            return

        if not raw:
            continue

        lowered = raw.lower()

        if lowered in {"quit", "exit"}:
            print("Goodbye.")
            return

        if lowered == "help":
            print_help()
            continue

        if lowered == "reset":
            reset_session()
            continue

        if lowered == "state":
            print_state()
            continue

        try:
            packet = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"{RED}[ERROR]{RESET} Invalid JSON: {e}")
            print("Type 'help' to see valid packet formats.")
            continue

        handle_packet(packet)


if __name__ == "__main__":
    try:
        repl()
    except KeyboardInterrupt:
        print("\nGoodbye.")
        sys.exit(0)
