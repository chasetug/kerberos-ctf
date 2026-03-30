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

FLAG1 = "FLAG{valid_ticket_chain}"
FLAG2 = "FLAG{pass_the_ticket_success}"

BANNER = f"""
{BOLD}Mini Kerberos CTF{RESET}

Hosts:
  A = KDC / Domain Controller
  B = Bob's Laptop
  C = Charlie's Workstation
  D = MySQL Server
  E = HTTP Server

Goals:
  FLAG 1: Connect to a service as a client.
  Submit the 3 packets in the correct order:
    1. AS-REQ
    2. TGS-REQ
    3. AP-REQ

  FLAG 2: Break my system by conducting a Pass-The-Ticket attack.
  Submit the 2 packets as before:
    1. AS-REQ
    2. TGS-REQ
  Then send the service ticket from a {BOLD}DIFFERENT{RESET} host:
    3. AP-REQ

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

1) AS-REQ
{{
  "src": "<host>",
  "dst": "<host>",
  "type": "AS-REQ",
  "user": "<user>"
}}

2) TGS-REQ
{{
  "src": "<host>",
  "dst": "<host>",
  "type": "TGS-REQ",
  "service": "<service>",
  "tgt": "<tgt>"
}}

3) AP-REQ
{{
  "src": "<host>",
  "dst": "<host>",
  "type": "AP-REQ",
  "service": "<service>",
  "service_ticket": "<service_ticket>"
}}

Notes:
- <host>:
    A, B, C, D, or E

- <user>:
   bob or charlie

- <service>:
   mysql or http

- Fill in the <parameters> yourself.
- The KDC will generate the <tgt> and <service_ticket> for you.
- Type the packet as a JSON string on a single line.
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

    if packet.get("type") != "AS-REQ":
        fail("Expected AS-REQ as the first packet.")
        return

    if src not in CLIENTS:
        fail("AS-REQ must come from a valid client (B or C).")
        return

    if dst != KDC:
        fail("AS-REQ must be sent to A.")
        return

    expected_user = CLIENTS[src]
    if user != expected_user:
        fail(f"AS-REQ user mismatch. Expected '{expected_user}' for client '{src}'.")
        return

    session["client"] = src
    session["user"] = expected_user
    session["tgt"] = make_tgt(expected_user)
    session["expected_step"] = 3

    print(f"{GREEN}[OK]{RESET} {src} -> {dst} AS-REQ accepted")
    print(f"AS-REP Received:{RESET}")
    pretty(
        {
            "src": "A",
            "dst": src,
            "type": "AS-REP",
            "tgt": session["tgt"],
        }
    )


def validate_service_req(packet: dict) -> None:
    src = packet.get("src")
    dst = packet.get("dst")
    service = packet.get("service")
    tgt = packet.get("tgt")

    if packet.get("type") != "TGS-REQ":
        fail("Expected TGS-REQ as the next packet.")
        return

    if src != session["client"]:
        fail("TGS-REQ must come from the same client that requested the TGT.")
        return

    if dst != KDC:
        fail("TGS-REQ must be sent to A.")
        return

    if service not in SERVICES:
        valid_services = ", ".join(sorted(SERVICES.keys()))
        fail(f"TGS-REQ must request a valid service ({valid_services}).")
        return

    if tgt != session["tgt"]:
        fail("TGS-REQ used an invalid or modified TGT.")
        return

    session["service"] = service
    session["service_host"] = SERVICES[service]
    session["service_ticket"] = make_service_ticket(session["user"], service)
    session["expected_step"] = 5

    print(f"{GREEN}[OK]{RESET} {src} -> {dst} TGS-REQ accepted")
    print(f"TGS-REP Received:{RESET}")
    pretty(
        {
            "src": "A",
            "dst": src,
            "type": "TGS-REP",
            "service": service,
            "service_ticket": session["service_ticket"],
        }
    )


def validate_app_req(packet: dict) -> None:
    src = packet.get("src")
    dst = packet.get("dst")
    service = packet.get("service")
    service_ticket = packet.get("service_ticket")

    if packet.get("type") != "AP-REQ":
        fail("Expected AP-REQ as the final packet.")
        return

    if src not in CLIENTS:
        fail("AP-REQ must come from a valid client (B or C).")
        return

    if dst != session["service_host"]:
        fail("AP-REQ must be sent to the correct host for the requested service.")
        return

    if service != session["service"]:
        fail("AP-REQ service does not match the service requested earlier.")
        return

    expected_host = SERVICES.get(service)
    if expected_host != dst:
        fail(f"AP-REQ host/service mismatch. Service '{service}' belongs on host '{expected_host}'.")
        return

    if service_ticket != session["service_ticket"]:
        fail("AP-REQ used an invalid or modified service ticket.")
        return

    session["complete"] = True
    is_pass_the_ticket = src != session["client"]
    awarded_flag = FLAG2 if is_pass_the_ticket else FLAG1

    print(f"{GREEN}[OK]{RESET} {src} -> {dst} AP-REQ accepted")

    if is_pass_the_ticket:
        print(
            f"{YELLOW}[PTT]{RESET} Pass-the-Ticket detected: "
            f"ticket originally issued to {session['client']} but replayed from {src}"
        )
    print(f"AP-REP Received:{RESET}")
    pretty(
        {
            "src": dst,
            "dst": src,
            "type": "AP-REP",
            "flag": awarded_flag,
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