#!/usr/bin/env python3
"""Read DNS records from AWS Route53 and emit an Azure DNS Bicep template.

The output is a Bicep file that declares the Azure DNS zone and one resource
per migrate-able record set. Incompatibilities (Route53 routing policies,
alias records, apex CNAMEs, unsupported types) are logged to stderr AND
emitted as comments inside the generated template so they're visible at
review time.

Usage:
    python route-53-to-azure-dns.py \\
        --source-zone <ZONE_ID> \\
        [--output <file.bicep>] \\
        [--zone-name <azure-zone-name>] \\
        [--alias-to-cname] \\
        [--aws-profile <name>] [--verbose]

Arguments:
    --source-zone     Route53 hosted zone ID. Must match the format
                      'Z' + uppercase letters/digits, optionally prefixed
                      with '/hostedzone/'. DNS names (example.com) are
                      NOT accepted — look the ID up first with
                      `aws route53 list-hosted-zones`.
    --output, -o      Path to write the generated Bicep file. Defaults
                      to '<zone-name>.bicep' in the current directory
                      (e.g. 'example.com.bicep').
    --zone-name       Azure DNS zone name used in the template. Defaults
                      to the Route53 zone's DNS name (trailing dot stripped).
    --alias-to-cname  Last-resort fallback for alias records: convert to
                      CNAME (except at the apex, per RFC 1034). Only kicks
                      in if the alias target is NOT a record in this zone
                      AND DNS resolution returns nothing.
                      Aliases are handled, in order:
                        1. In-zone target -> Azure DNS alias record set
                           (targetResource.id points at the local Bicep
                           resource). Works at the apex.
                        2. Out-of-zone target (or in-zone with no matching
                           type) -> DNS-resolve via the system resolver
                           and pin as a normal A/AAAA record.
                        3. --alias-to-cname only here -> CNAME.
    --aws-profile     AWS named profile. Falls back to the default boto3
                      credential chain (env vars, ~/.aws/credentials, IAM
                      role, SSO, etc.) when omitted.
    --verbose, -v     Verbose logging. Without it, only warnings and
                      errors are shown (in red on a terminal). Set the
                      NO_COLOR environment variable to disable color.

Examples:
    # Default: writes ./<zone-name>.bicep, shows only warnings/errors
    python route-53-to-azure-dns.py --source-zone Z1234567890ABC

    # Write to a file, convert aliases, use a named AWS profile
    python route-53-to-azure-dns.py \\
        --source-zone Z1234567890ABC \\
        --output example.bicep \\
        --zone-name example.com \\
        --alias-to-cname \\
        --aws-profile production

    # Look up the zone ID first if you only know the domain name
    aws route53 list-hosted-zones \\
        --query "HostedZones[?Name=='example.com.'].Id" --output text

Deploy the generated template:
    az deployment group create \\
        --resource-group <rg> \\
        --template-file example.bicep \\
        --parameters zoneName=example.com

Exit codes:
    0  success
    1  Route53 / AWS error
    2  invalid --source-zone format

Auth: boto3 default credential chain (or --aws-profile). Azure auth is
not required — this script never calls Azure; it only generates a
template you deploy yourself.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import socket
import sys
from dataclasses import dataclass, field
from typing import Iterator

import boto3
from botocore.exceptions import BotoCoreError, ClientError


BICEP_API_VERSION = "2018-05-01"

ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_RESET = "\033[0m"


class LevelColorFormatter(logging.Formatter):
    """Color log lines by level: ERROR+ red, WARNING yellow, others uncolored.

    Color is only applied when stderr is an actual terminal and NO_COLOR isn't
    set, so piping or redirecting output stays clean.
    """

    def __init__(self, use_color: bool) -> None:
        super().__init__(fmt="%(levelname)s %(message)s")
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if not self.use_color:
            return msg
        if record.levelno >= logging.ERROR:
            return f"{ANSI_RED}{msg}{ANSI_RESET}"
        if record.levelno == logging.WARNING:
            return f"{ANSI_YELLOW}{msg}{ANSI_RESET}"
        return msg

AZURE_SUPPORTED_TYPES = {
    "A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT",
}

# Azure DNS alias records (those backed by `targetResource` instead of literal
# values) are only defined for A, AAAA, and CNAME record sets.
AZURE_ALIAS_TYPES = {"A", "AAAA", "CNAME"}

ROUTE53_ROUTING_POLICY_FIELDS = {
    "Weight": "Weighted",
    "Region": "Latency",
    "Failover": "Failover",
    "GeoLocation": "Geolocation",
    "GeoProximityLocation": "Geoproximity",
    "MultiValueAnswer": "Multivalue answer",
}


@dataclass
class Report:
    emitted: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (label, reason)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return f"emitted={len(self.emitted)} skipped={len(self.skipped)} notes={len(self.notes)}"


# ---------------------------------------------------------------------------
# Route53
# ---------------------------------------------------------------------------

# Route53 hosted zone IDs are alphanumeric strings (uppercase, 13–32 chars in
# practice) starting with 'Z'. The API also accepts the prefixed form
# '/hostedzone/<ID>'. Anything else — bare DNS names, lowercase, dots — is
# rejected up front so we never accidentally do a name-based lookup.
ZONE_ID_RE = re.compile(r"^(?:/hostedzone/)?(Z[A-Z0-9]{8,})$")


def is_valid_zone_id(value: str) -> bool:
    return ZONE_ID_RE.match(value) is not None


def normalize_zone_id(value: str) -> str:
    """Strip the optional '/hostedzone/' prefix. Caller must validate first."""
    return value.split("/")[-1]


def resolve_zone(client, zone_id: str) -> dict:
    try:
        return client.get_hosted_zone(Id=zone_id)["HostedZone"]
    except ClientError as exc:
        raise SystemExit(f"error: could not load Route53 hosted zone {zone_id!r}: {exc}")


def iter_record_sets(client, zone_id: str) -> Iterator[dict]:
    paginator = client.get_paginator("list_resource_record_sets")
    for page in paginator.paginate(HostedZoneId=zone_id):
        yield from page["ResourceRecordSets"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def detect_routing_policy(rrset: dict) -> str | None:
    for field_name, label in ROUTE53_ROUTING_POLICY_FIELDS.items():
        if field_name in rrset:
            return label
    if "SetIdentifier" in rrset:
        return "Non-simple (SetIdentifier present)"
    return None


def relative_name(name: str, origin: str) -> str:
    """Azure DNS uses relative names; '@' is the zone apex."""
    name = name.replace("\\052", "*")
    if name == origin:
        return "@"
    if name.endswith("." + origin):
        return name[: -(len(origin) + 1)]
    return name.rstrip(".")


def bicep_symbol(rtype: str, name: str, taken: set[str]) -> str:
    """Build a unique, syntactically-valid Bicep symbol for a record."""
    slug = name
    slug = slug.replace("@", "apex")
    slug = slug.replace("*", "wildcard")
    slug = re.sub(r"[^A-Za-z0-9]+", "_", slug).strip("_") or "rec"
    base = f"{rtype.lower()}_{slug}"
    candidate = base
    i = 2
    while candidate in taken:
        candidate = f"{base}_{i}"
        i += 1
    taken.add(candidate)
    return candidate


def bicep_str(value: str) -> str:
    """Bicep single-quoted string with minimal escaping."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


# ---------------------------------------------------------------------------
# Parsers for Route53 RDATA strings
# ---------------------------------------------------------------------------

def _parse_txt(value: str) -> list[str]:
    """Route53 TXT values are RFC 1035 character-strings — possibly multiple
    quoted segments separated by whitespace. Azure wants the unquoted parts."""
    parts: list[str] = []
    buf: list[str] = []
    in_quotes = False
    escape = False
    for ch in value:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            if in_quotes:
                parts.append("".join(buf))
                buf = []
            in_quotes = not in_quotes
            continue
        if in_quotes:
            buf.append(ch)
    return parts or [value]


def _parse_mx(value: str) -> tuple[int, str]:
    pref, exch = value.split(None, 1)
    return int(pref), exch.rstrip(".")


def _parse_srv(value: str) -> tuple[int, int, int, str]:
    pri, w, port, tgt = value.split()
    return int(pri), int(w), int(port), tgt.rstrip(".")


def _parse_caa(value: str) -> tuple[int, str, str]:
    flags, tag, val = value.split(None, 2)
    return int(flags), tag, val.strip('"')


# ---------------------------------------------------------------------------
# Bicep emission
# ---------------------------------------------------------------------------

def render_properties(rtype: str, ttl: int, values: list[str]) -> str:
    """Return the Bicep `properties: { ... }` block body (no surrounding braces)."""
    indent = "    "
    lines = [f"{indent}TTL: {ttl}"]

    def list_block(key: str, items: list[str]) -> None:
        lines.append(f"{indent}{key}: [")
        for item in items:
            lines.append(f"{indent}  {item}")
        lines.append(f"{indent}]")

    if rtype == "A":
        list_block("ARecords", [f"{{ ipv4Address: {bicep_str(v)} }}" for v in values])
    elif rtype == "AAAA":
        list_block("AAAARecords", [f"{{ ipv6Address: {bicep_str(v)} }}" for v in values])
    elif rtype == "CNAME":
        lines.append(f"{indent}CNAMERecord: {{ cname: {bicep_str(values[0].rstrip('.'))} }}")
    elif rtype == "MX":
        records = []
        for v in values:
            pref, exch = _parse_mx(v)
            records.append(f"{{ preference: {pref}, exchange: {bicep_str(exch)} }}")
        list_block("MXRecords", records)
    elif rtype == "NS":
        list_block("NSRecords", [f"{{ nsdname: {bicep_str(v.rstrip('.'))} }}" for v in values])
    elif rtype == "PTR":
        list_block("PTRRecords", [f"{{ ptrdname: {bicep_str(v.rstrip('.'))} }}" for v in values])
    elif rtype == "SRV":
        records = []
        for v in values:
            pri, w, port, tgt = _parse_srv(v)
            records.append(
                f"{{ priority: {pri}, weight: {w}, port: {port}, target: {bicep_str(tgt)} }}"
            )
        list_block("SRVRecords", records)
    elif rtype == "TXT":
        records = []
        for v in values:
            parts = _parse_txt(v)
            inner = ", ".join(bicep_str(p) for p in parts)
            records.append(f"{{ value: [ {inner} ] }}")
        list_block("TXTRecords", records)
    elif rtype == "CAA":
        records = []
        for v in values:
            flags, tag, val = _parse_caa(v)
            records.append(
                f"{{ flags: {flags}, tag: {bicep_str(tag)}, value: {bicep_str(val)} }}"
            )
        list_block("caaRecords", records)
    else:
        raise ValueError(f"unsupported record type: {rtype}")

    return "\n".join(lines)


def emit_record_resource(symbol: str, rtype: str, name: str, body: str) -> str:
    return (
        f"resource {symbol} 'Microsoft.Network/dnsZones/{rtype}@{BICEP_API_VERSION}' = {{\n"
        f"  parent: zone\n"
        f"  name: {bicep_str(name)}\n"
        f"  properties: {{\n"
        f"{body}\n"
        f"  }}\n"
        f"}}\n"
    )


def emit_alias_record(
    symbol: str, rtype: str, name: str, ttl: int, target_symbol: str
) -> str:
    """Azure DNS alias record set pointing to another record set in the same
    zone, referenced by Bicep symbol so the deployment links the two resources
    via `targetResource.id`."""
    return (
        f"resource {symbol} 'Microsoft.Network/dnsZones/{rtype}@{BICEP_API_VERSION}' = {{\n"
        f"  parent: zone\n"
        f"  name: {bicep_str(name)}\n"
        f"  properties: {{\n"
        f"    TTL: {ttl}\n"
        f"    targetResource: {{ id: {target_symbol}.id }}\n"
        f"  }}\n"
        f"}}\n"
    )


def resolve_dns(name: str, rtype: str) -> list[str] | None:
    """Resolve `name` to A or AAAA addresses via the system resolver.

    Returns sorted unique addresses, or None when `rtype` isn't A/AAAA, the
    resolver fails, or no records exist. Used to flatten out-of-zone Route53
    alias targets (typically AWS resources like ELB or CloudFront) into a
    static address list — pinned at template-generation time, so it should be
    re-run if those upstream IPs are expected to change.
    """
    if rtype == "A":
        family = socket.AF_INET
    elif rtype == "AAAA":
        family = socket.AF_INET6
    else:
        return None
    try:
        infos = socket.getaddrinfo(name, None, family=family, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    addrs = sorted({info[4][0] for info in infos})
    return addrs or None


def build_template(
    zone_name: str,
    record_sets: list[dict],
    origin: str,
    *,
    alias_to_cname: bool,
    log: logging.Logger,
) -> tuple[str, Report]:
    report = Report()
    body: list[str] = []
    taken: set[str] = set()

    # SPF (RR type 99) was deprecated by RFC 7208 in favor of TXT. Azure DNS
    # never supported the legacy SPF type, so we convert SPF -> TXT — but
    # only if there's no existing TXT at the same name (Azure record sets are
    # unique per (name, type), and folding SPF data into an existing TXT could
    # silently overwrite it).
    txt_names = {
        relative_name(rs["Name"], origin)
        for rs in record_sets
        if rs["Type"] == "TXT"
    }

    # (relative name, Azure record type) -> Bicep symbol for every non-alias
    # record set we emit. Populated during pass 1 so pass 2 (alias records)
    # can wire `targetResource.id` to local targets via the Bicep symbol.
    target_symbols: dict[tuple[str, str], str] = {}

    body.append("// Auto-generated from AWS Route53.")
    body.append(f"// Source zone: {origin}")
    body.append("// Review carefully before deploying — any incompatibilities are noted inline.\n")
    body.append(f"param zoneName string = {bicep_str(zone_name)}\n")
    body.append(
        f"resource zone 'Microsoft.Network/dnsZones@{BICEP_API_VERSION}' = {{\n"
        f"  name: zoneName\n"
        f"  location: 'global'\n"
        f"}}\n"
    )

    def skip(label: str, reason: str, level: int = logging.ERROR) -> None:
        log.log(level, f"{label}: {reason}")
        report.skipped.append((label, reason))
        body.append(f"// SKIPPED {label}: {reason}\n")

    def note(text: str) -> None:
        log.warning(text)
        report.notes.append(text)
        body.append(f"// NOTE {text}\n")

    # Pass 1: non-alias records. Aliases need to reference local targets, so
    # we materialize every non-alias record first and record its Bicep symbol.
    for rrset in record_sets:
        if "AliasTarget" in rrset:
            continue

        rtype = rrset["Type"]
        name = relative_name(rrset["Name"], origin)
        label = f"{name} {rtype}"
        ttl = rrset.get("TTL", 3600)

        policy = detect_routing_policy(rrset)
        if policy:
            skip(label, f"Route53 routing policy '{policy}' is not supported by "
                        "Azure DNS. Use Azure Traffic Manager or Azure Front Door.")
            continue

        # Apex SOA/NS are Azure-managed.
        if name == "@" and rtype in {"SOA", "NS"}:
            skip(label, f"Azure DNS manages apex {rtype} automatically.",
                 level=logging.INFO)
            continue

        # SPF -> TXT (RFC 7208 deprecated the SPF RR type).
        if rtype == "SPF":
            values = [r["Value"] for r in rrset.get("ResourceRecords", [])]
            if name in txt_names:
                skip(label,
                     "SPF record type is deprecated (RFC 7208) and not supported "
                     "by Azure DNS. A TXT record already exists at this name; "
                     "verify it carries the SPF policy and remove this SPF "
                     "record at the source.")
                continue
            note(f"{label}: SPF type deprecated (RFC 7208); converted to TXT "
                 "at the same name.")
            try:
                props = render_properties("TXT", ttl, values)
            except Exception as exc:
                skip(label, f"failed to render SPF->TXT properties: {exc}")
                continue
            sym = bicep_symbol("TXT", name, taken)
            target_symbols[(name, "TXT")] = sym
            body.append(emit_record_resource(sym, "TXT", name, props))
            report.emitted.append(label)
            txt_names.add(name)  # so a later TXT at the same name is detected
            continue

        if rtype not in AZURE_SUPPORTED_TYPES:
            skip(label, "record type not supported by Azure DNS.")
            continue

        values = [r["Value"] for r in rrset.get("ResourceRecords", [])]
        if not values:
            skip(label, "no ResourceRecords on a non-alias record set.")
            continue

        try:
            props = render_properties(rtype, ttl, values)
        except Exception as exc:
            skip(label, f"failed to render properties: {exc}")
            continue

        sym = bicep_symbol(rtype, name, taken)
        target_symbols[(name, rtype)] = sym
        body.append(emit_record_resource(sym, rtype, name, props))
        report.emitted.append(label)

    # Pass 2: alias records. Now that target_symbols is complete, an in-zone
    # alias whose target is a record we emitted in pass 1 becomes an Azure DNS
    # alias record set (targetResource.id -> sibling resource). Otherwise we
    # try a live DNS lookup and pin the result as a normal A/AAAA record.
    # Last resort: --alias-to-cname converts to CNAME, else we skip.
    for rrset in record_sets:
        if "AliasTarget" not in rrset:
            continue

        rtype = rrset["Type"]
        name = relative_name(rrset["Name"], origin)
        label = f"{name} {rtype}"
        ttl = rrset.get("TTL", 3600)

        policy = detect_routing_policy(rrset)
        if policy:
            skip(label, f"Route53 routing policy '{policy}' is not supported by "
                        "Azure DNS. Use Azure Traffic Manager or Azure Front Door.")
            continue

        target_full = rrset["AliasTarget"]["DNSName"]
        if not target_full.endswith("."):
            target_full = target_full + "."
        target = target_full.rstrip(".")

        # Same-zone alias -> Azure DNS alias record (only A/AAAA/CNAME types
        # support targetResource). Works at the apex too — Azure alias records
        # are valid there, unlike CNAMEs (RFC 1034).
        in_zone = target_full == origin or target_full.endswith("." + origin)
        if in_zone and rtype in AZURE_ALIAS_TYPES:
            target_rel = relative_name(target_full, origin)
            target_sym = target_symbols.get((target_rel, rtype))
            if target_sym:
                note(f"{label}: emitted as Azure DNS alias -> local {rtype} "
                     f"record {target_rel!r} ({target_sym})")
                sym = bicep_symbol(rtype, name, taken)
                body.append(emit_alias_record(sym, rtype, name, ttl, target_sym))
                report.emitted.append(label)
                continue

        # Otherwise resolve the target via DNS and pin the addresses. Only
        # meaningful for A/AAAA — other types fall through.
        resolved = resolve_dns(target, rtype)
        if resolved:
            note(f"{label}: resolved alias target {target!r} via DNS to "
                 f"{len(resolved)} {rtype} value(s); pinned at generation time "
                 "— re-run if those upstream IPs change.")
            try:
                props = render_properties(rtype, ttl, resolved)
            except Exception as exc:
                skip(label, f"failed to render resolved alias properties: {exc}")
                continue
            sym = bicep_symbol(rtype, name, taken)
            body.append(emit_record_resource(sym, rtype, name, props))
            report.emitted.append(label)
            continue

        # Final fallback: convert to CNAME (if opted in and not at apex), else skip.
        if not alias_to_cname:
            skip(label,
                 f"Route53 alias to {target!r} has no direct Azure equivalent "
                 "and DNS resolution returned nothing. Re-run with "
                 "--alias-to-cname to fall back to a CNAME, or create the "
                 "Azure record manually.")
            continue
        if name == "@":
            skip(label,
                 f"apex alias to {target!r} cannot become a CNAME (RFC 1034 "
                 "forbids CNAME at the zone apex) and DNS resolution returned "
                 "nothing. Create an Azure DNS alias record set pointing to an "
                 "Azure resource instead.")
            continue
        note(f"{label}: converted Route53 alias -> CNAME ({target})")
        sym = bicep_symbol("CNAME", name, taken)
        props = render_properties("CNAME", ttl, [target])
        body.append(emit_record_resource(sym, "CNAME", name, props))
        report.emitted.append(label)

    return "\n".join(body) + "\n", report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate an Azure DNS Bicep template from a Route53 hosted zone.",
    )
    parser.add_argument("--source-zone", required=True,
                        help="Route53 hosted zone ID (e.g. Z1234567890ABC or "
                             "/hostedzone/Z1234567890ABC). DNS names are not accepted.")
    parser.add_argument("--output", "-o",
                        help="Output Bicep file path. Defaults to "
                             "'<zone-name>.bicep' in the current directory.")
    parser.add_argument("--zone-name",
                        help="Azure DNS zone name (defaults to the Route53 zone name).")
    parser.add_argument("--alias-to-cname", action="store_true",
                        help="Last-resort CNAME fallback for aliases whose "
                             "target is neither in-zone nor DNS-resolvable. "
                             "In-zone aliases always become Azure DNS alias "
                             "records; out-of-zone aliases are resolved and "
                             "pinned as A/AAAA first.")
    parser.add_argument("--aws-profile",
                        help="AWS profile name (default credential chain otherwise).")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose logging.")
    args = parser.parse_args()

    # By default only WARNING+ is shown, and those lines are red on a TTY.
    # --verbose drops the level to DEBUG so the full INFO trail appears too.
    use_color = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(LevelColorFormatter(use_color=use_color))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if args.verbose else logging.WARNING)
    log = logging.getLogger("r53-to-bicep")

    if not is_valid_zone_id(args.source_zone):
        log.error(
            f"--source-zone {args.source_zone!r} is not a valid Route53 hosted "
            "zone ID. Expected format: 'Z' followed by uppercase letters and "
            "digits (e.g. Z1234567890ABC), optionally prefixed with "
            "'/hostedzone/'."
        )
        return 2
    zone_id = normalize_zone_id(args.source_zone)

    try:
        session = boto3.Session(profile_name=args.aws_profile) if args.aws_profile else boto3.Session()
        r53 = session.client("route53")
        zone = resolve_zone(r53, zone_id)
        origin = zone["Name"]
        record_sets = list(iter_record_sets(r53, zone["Id"]))
        log.info(f"loaded {len(record_sets)} record sets from Route53 zone {origin}")
    except (BotoCoreError, ClientError) as exc:
        log.error(f"Route53 error: {exc}")
        return 1

    zone_name = args.zone_name or origin.rstrip(".")
    template, report = build_template(
        zone_name, record_sets, origin,
        alias_to_cname=args.alias_to_cname,
        log=log,
    )

    output_path = args.output or f"{zone_name}.bicep"
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(template)
    log.info(f"wrote template to {output_path}")

    log.info(f"done: {report.summary()}")
    if report.skipped:
        log.info("skipped items:")
        for label, reason in report.skipped:
            log.info(f"  - {label}: {reason}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
