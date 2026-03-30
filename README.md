# Kerberos CTF

This is a mini CTF challenge I created for a Kerberos presentation at Auburn University's Ethical Hacking Club.

The goal is to both **understand Kerberos authentication** and **identify how it can be abused**.

---

## Learning Objectives

- Understand the Kerberos authentication flow:
  - AS-REQ / AS-REP
  - TGS-REQ / TGS-REP
  - AP-REQ / AP-REP
- Learn how Ticket Granting Tickets (TGTs) and Service Tickets work
- See how improper validation can lead to **Pass-the-Ticket attacks**

---

## Flags

### FLAG 1 — Legitimate Authentication
Obtain this flag by correctly following the Kerberos protocol:

1. Send an **AS-REQ** to the KDC  
2. Use the returned TGT in a **TGS-REQ**  
3. Use the service ticket in an **AP-REQ** to the correct service  

This demonstrates normal Kerberos behavior.

---

### FLAG 2 — Pass-the-Ticket Attack
Obtain this flag by abusing the system:

1. Perform AS-REQ and TGS-REQ as normal  
2. Take the issued **service ticket**  
3. Replay it from a **different host**  

If successful, you will authenticate as another user without credentials.

---

## Hosts

| Host | Description |
|------|------------|
| A | KDC / Domain Controller |
| B | Bob's Laptop |
| C | Charlie's Workstation |
| D | MySQL Server |
| E | HTTP Server |

---

## Running the Challenge

```bash
python3 kerb_ctf.py
```
---

Then input packets as JSON:

## Packet Format

### AS-REQ
```json
{"src":"<host>","dst":"A","type":"AS-REQ","user":"<user>"}
````

### TGS-REQ
```json
{"src":"<host>","dst":"A","type":"TGS-REQ","service":"<service>","tgt":"<TGT>"}
````

### AP-REQ
```json
{"src":"<host>","dst":"<service_host>","type":"AP-REQ","service":"<service>","service_ticket":"<ST>"}
````

---

## Example (FLAG 1 — Normal Flow)

```json
{"src":"B","dst":"A","type":"AS-REQ","user":"bob"}
{"src":"B","dst":"A","type":"TGS-REQ","service":"mysql","tgt":"TGT_BOB_8B9F10"}
{"src":"B","dst":"D","type":"AP-REQ","service":"mysql","service_ticket":"ST_BOB_MYSQL_E9D7AC"}
```

---

## Example (FLAG 2 — Pass-the-Ticket)

```json
{"src":"C","dst":"A","type":"AS-REQ","user":"charlie"}
{"src":"C","dst":"A","type":"TGS-REQ","service":"http","tgt":"TGT_CHARLIE_8B9F10"}
{"src":"B","dst":"E","type":"AP-REQ","service":"http","service_ticket":"ST_CHARLIE_HTTP_E9D7AC"}
```

---

## Notes

- All packets must be valid JSON (quotes matter)
- The system is stateful — incorrect steps reset the session
- You must use tickets exactly as returned by the KDC
- Service tickets only work for:
  - the correct **service**
  - the correct **destination host**

---

## Key Takeaway

Kerberos does not verify **where** a ticket is used — only that it is valid.

This allows attackers to reuse stolen tickets:
→ **Pass-the-Ticket attack**