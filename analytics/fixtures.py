"""Deterministic, synthetic sign-in and SaaS audit traces."""

import hashlib
import json
from dataclasses import dataclass

EPOCH = 1_740_000_000_000
MIN = 60_000
DAY = 1440 * MIN


@dataclass(frozen=True)
class Incident:
    rule: str
    start: int
    triggers: frozenset[str]


def traces():
    events, incidents = [], []

    def add(uid, offset, account, kind="login", outcome="success",
            ip="192.0.2.1", asn="64496", device="device-a", lat=None, lon=None,
            scope="", token=""):
        event = {
            "time": EPOCH + offset,
            "actor": {"user": {"uid": account}},
            "metadata": {"uid": uid, "product": {"name": "synthetic"}},
            "src_endpoint": dict(ip=ip, asn=asn, device=device, latitude=lat, longitude=lon),
            "unmapped": dict(kind=kind, outcome=outcome, scope=scope, token=token),
        }
        event["payload_sha256"] = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
        events.append(event)

    def mark(rule, offset, *uids):
        incidents.append(Incident(rule, EPOCH + offset, frozenset(uids)))

    for day in range(3):
        base = day * DAY
        for i in range(480):
            add(f"base-{day}-{i}", base + i * MIN, f"person-{i % 45}",
                outcome="failure" if i % 17 == 0 else "success",
                ip=f"198.51.100.{i % 64 + 1}", lat=51.5, lon=-0.12)
        add(f"vpn-normal-{day}", base, f"vpn-{day}", lat=51.5, lon=-0.12)
        add(f"vpn-egress-{day}", base + 2 * MIN, f"vpn-{day}", asn="64512", lat=40.7, lon=-74)
        add(f"readonly-{day}", base + MIN, f"vpn-{day}", kind="oauth_grant", scope="Calendar.Read")
        add(f"sender-{day}", base + MIN, "approved-integration", kind="oauth_grant",
            scope="unrelated/Calendar.ReadWrite")
        begin = base + 720 * MIN
        slow_begin = base + 960 * MIN
        for i in range(8):
            add(f"spray-{day}-{i}", begin + i * MIN, f"spray-user-{i}",
                outcome="failure", ip="203.0.113.11")
            add(f"slow-{day}-{i}", slow_begin + i * 10 * MIN, f"slow-user-{i}",
                outcome="failure", ip=f"203.0.113.{12 + i % 4}")
        mark("password_spray", begin, f"spray-{day}-7")
        mark("distributed_password_spray", slow_begin, f"slow-{day}-7")
        for i in range(3):
            add(f"deny-{day}-{i}", begin + i * MIN, "fatigue", "mfa_push", "deny")
        add(f"accept-{day}", begin + 3 * MIN, "fatigue", "mfa_push", "accept",
            ip="203.0.113.10", asn="64497")
        mark("mfa_fatigue", begin, f"accept-{day}")
        add(f"leg-a-{day}", begin, "traveler", lat=51.5, lon=-0.12)
        add(f"leg-b-{day}", begin + 15 * MIN, "traveler", lat=40.7, lon=-74)
        mark("impossible_travel", begin, f"leg-b-{day}")
        add(f"grant-{day}", begin, "oauth-admin", "oauth_grant",
            scope=["Calendar.ReadWrite", "https://www.googleapis.com/auth/calendar", "bulk_export"][day])
        mark("scope_escalation", begin, f"grant-{day}")
        add(f"private-share-{day}", begin, "notion-admin", "share", scope="private")
        add(f"public-share-{day}", begin, "notion-admin", "share", scope="public_share")
        mark("scope_escalation", begin, f"public-share-{day}")
        add(f"token-first-{day}", begin, "token-user", token=f"session-{day}")
        add(f"mutated-vendor-id-{day}", begin + MIN, "token-user",
            token=f"session-{day}", asn="64498", device="device-b")
        mark("token_replay", begin, f"mutated-vendor-id-{day}")
        events.append(dict(events[-1]))
        add(f"reissued-vendor-id-{day}", begin + MIN, "token-user",
            token=f"session-{day}", asn="64498", device="device-b")
    return events, incidents
