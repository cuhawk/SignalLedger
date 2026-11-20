"""Normalize CloudTrail and Okta System Log exports into OCSF 1.1 events."""

from datetime import datetime, timedelta, timezone
import hashlib
from ipaddress import ip_address
import json


AWS = {
    "AssumeRole": (6003, 1, "assume_role"),
    "CreateAccessKey": (6003, 1, "create_access_key"),
    "ConsoleLogin": (3002, 1, "login"),
}
OKTA = {
    "user.session.start": (3002, 1, "login"),
    "policy.evaluate_sign_on": (3003, 99, "sign_on_policy"),
}
PRODUCTS = {"cloudtrail": ("AWS", "CloudTrail"), "okta": ("Okta", "Okta System Log")}


def obj(value):
    return value if isinstance(value, dict) else {}


def text(value):
    return value if isinstance(value, str) and value.strip() else None


def normalize(vendor, raw):
    if not isinstance(raw, dict):
        raise ValueError("expected an event object")
    if vendor == "cloudtrail":
        name = text(raw.get("eventName"))
        if not name:
            raise ValueError("missing eventName")
        if name not in AWS:
            return None
        identity = obj(raw.get("userIdentity"))
        uid = text(identity.get("principalId")) or text(identity.get("arn")) or text(identity.get("accountId"))
        user_name = text(identity.get("userName"))
        event_id, timestamp = raw.get("eventID"), raw.get("eventTime")
        ip = raw.get("sourceIPAddress")
        class_id, activity, kind = AWS[name]
        result = obj(raw.get("responseElements")).get("ConsoleLogin")
        if raw.get("errorCode") or raw.get("errorMessage") or result == "Failure":
            outcome = "failure"
        elif name != "ConsoleLogin" or result == "Success":
            outcome = "success"
        else:
            outcome = "unknown"
        unmapped = {"identity_type": text(identity.get("type")),
                    "mfa_used": text(obj(raw.get("additionalEventData")).get("MFAUsed")),
                    "source_address": text(ip)}
    elif vendor == "okta":
        name = text(raw.get("eventType"))
        if not name:
            raise ValueError("missing eventType")
        if name not in OKTA:
            return None
        identity = obj(raw.get("actor"))
        uid = text(identity.get("id")) or text(identity.get("alternateId"))
        user_name = text(identity.get("alternateId"))
        event_id, timestamp = raw.get("uuid"), raw.get("published")
        client = obj(raw.get("client"))
        ip = client.get("ipAddress")
        class_id, activity, kind = OKTA[name]
        result = obj(raw.get("outcome")).get("result")
        if result in ("SUCCESS", "ALLOW"):
            outcome = "success"
        elif result in ("FAILURE", "DENY"):
            outcome = "failure"
        else:
            outcome = "unknown"
        security = obj(raw.get("securityContext"))
        proxy = security.get("isProxy")
        unmapped = {"is_proxy": proxy if isinstance(proxy, bool) else None,
                    "policy_result": text(result) if kind == "sign_on_policy" else None}
    else:
        raise ValueError(f"unsupported native vendor {vendor!r}")

    if not text(event_id) or not text(timestamp):
        raise ValueError("missing event identifier or timestamp")
    try:
        instant = datetime.fromisoformat(timestamp)
        if instant.utcoffset() is None:
            raise ValueError("timezone required")
        delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    except (ValueError, OverflowError) as err:
        raise ValueError(f"invalid event timestamp {timestamp!r}") from err
    try:
        address = str(ip_address(text(ip)))
    except ValueError:
        address = None

    user = {key: value for key, value in {"uid": uid, "name": user_name}.items() if value}
    endpoint = {"ip": address} if address else {}
    if vendor == "okta":
        asn = security.get("asNumber")
        if type(asn) is int and asn > 0:
            endpoint["asn"] = str(asn)
    vendor_name, product = PRODUCTS[vendor]
    unmapped.update(kind=kind, outcome=outcome, event_name=name)
    event = {
        "time": delta // timedelta(milliseconds=1),
        "category_uid": class_id // 1000,
        "class_uid": class_id,
        "activity_id": activity,
        "type_uid": class_id * 100 + activity,
        "severity_id": 0,
        "status_id": {"success": 1, "failure": 2, "unknown": 0}[outcome],
        "actor": {"user": user},
        "metadata": {"uid": event_id, "version": "1.1.0",
                     "product": {"name": product, "vendor_name": vendor_name}},
        "src_endpoint": endpoint,
        "unmapped": {key: value for key, value in unmapped.items() if value is not None},
        "payload_sha256": hashlib.sha256(json.dumps(
            raw, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
    }
    if class_id == 3002:
        event["user"] = user
    if class_id == 3003:
        event["activity_name"] = name
        event["user"] = user
    if class_id == 6003:
        event["api"] = {"operation": name}
        service = text(raw.get("eventSource"))
        if service:
            event["api"]["service"] = {"name": service}
    return event


def read_events(path, vendor):
    """Read a JSON object/array, CloudTrail Records envelope or JSONL stream."""
    with path.open(encoding="utf-8-sig") as source:
        if path.suffix.lower() in (".jsonl", ".ndjson"):
            documents = ((line_no, line) for line_no, line in enumerate(source, 1) if line.strip())
        else:
            documents = [(1, source.read())]
        for line_no, document in documents:
            try:
                value = json.loads(document)
                if vendor == "cloudtrail" and isinstance(value, dict) and "Records" in value:
                    value = value["Records"]
                    if not isinstance(value, list):
                        raise ValueError("CloudTrail Records must be an array")
            except ValueError as err:
                raise ValueError(f"{path}:{line_no}: {err}") from err
            for index, raw in enumerate(value if isinstance(value, list) else [value], 1):
                try:
                    event = normalize(vendor, raw)
                except ValueError as err:
                    raise ValueError(f"{path}:{line_no}: event {index}: {err}") from err
                if event is not None:
                    yield event
