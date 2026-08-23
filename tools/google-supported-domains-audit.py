#!/usr/bin/env python3
"""Benchmark and audit asyncwhois against Google's supported domains list."""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import asyncwhois
from asyncwhois.parse import TLDBaseKeys

SUPPORTED_DOMAINS_URL = "https://www.google.com/supported_domains"
DEFAULT_OUTPUT = ROOT / "state" / "google-supported-domains-audit.json"
KEYS_OF_INTEREST = [
    TLDBaseKeys.DOMAIN_NAME,
    TLDBaseKeys.NAME_SERVERS,
    TLDBaseKeys.REGISTRAR,
    TLDBaseKeys.CREATED,
    TLDBaseKeys.EXPIRES,
    TLDBaseKeys.STATUS,
]


@dataclass
class AuditResult:
    domain: str
    tld: str
    status: str
    seconds: float
    parsed_keys: list[str]
    ns_count: int
    error: str | None = None


def fetch_google_supported_domains() -> list[str]:
    html = urlopen(SUPPORTED_DOMAINS_URL).read().decode("utf-8", "ignore")
    domains = re.findall(r"\.google\.[a-z0-9.]+", html)
    return list(dict.fromkeys(d.lstrip(".") for d in domains))


def audit_domain(domain: str, timeout: int) -> AuditResult:
    start = time.perf_counter()
    try:
        _, parsed = asyncwhois.whois(domain, timeout=timeout)
        nameservers = parsed.get(TLDBaseKeys.NAME_SERVERS)
        if isinstance(nameservers, list):
            ns_count = len([ns for ns in nameservers if ns])
        elif nameservers:
            ns_count = 1
        else:
            ns_count = 0
        parsed_keys = [str(k) for k, v in parsed.items() if v not in (None, [], "")]
        return AuditResult(
            domain=domain,
            tld=domain.split(".")[-1],
            status="ok",
            seconds=time.perf_counter() - start,
            parsed_keys=sorted(parsed_keys),
            ns_count=ns_count,
        )
    except Exception as exc:
        return AuditResult(
            domain=domain,
            tld=domain.split(".")[-1],
            status="error",
            seconds=time.perf_counter() - start,
            parsed_keys=[],
            ns_count=0,
            error=repr(exc),
        )


def summarize(results: list[AuditResult]) -> dict:
    oks = [r for r in results if r.status == "ok"]
    errs = [r for r in results if r.status != "ok"]
    ordered = sorted(r.seconds for r in results)
    p90_index = max(0, min(len(ordered) - 1, int(len(ordered) * 0.9) - 1)) if ordered else 0

    by_tld: dict[str, Counter] = defaultdict(Counter)
    for row in oks:
        counter = by_tld[row.tld]
        counter["count"] += 1
        counter["has_nameservers"] += int(row.ns_count > 0)
        for key in row.parsed_keys:
            counter[key] += 1

    return {
        "domains_tested": len(results),
        "ok": len(oks),
        "errors": len(errs),
        "median_seconds": statistics.median(ordered) if ordered else None,
        "p90_seconds": ordered[p90_index] if ordered else None,
        "missing_nameservers": [r.domain for r in oks if r.ns_count == 0],
        "errors_list": [asdict(r) for r in errs],
        "by_tld": {tld: dict(counter) for tld, counter in sorted(by_tld.items())},
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=10, help="Per-domain WHOIS timeout in seconds")
    parser.add_argument("--limit", type=int, default=None, help="Only test the first N supported domains")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Where to write the JSON report")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-domain progress output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    domains = fetch_google_supported_domains()
    if args.limit is not None:
        domains = domains[: args.limit]

    results: list[AuditResult] = []
    for idx, domain in enumerate(domains, start=1):
        result = audit_domain(domain, timeout=args.timeout)
        results.append(result)
        if not args.quiet:
            suffix = f" {result.error}" if result.error else ""
            print(
                f"{idx}/{len(domains)} {result.domain} {result.status} {result.seconds:.2f}s ns={result.ns_count}{suffix}",
                flush=True,
            )

    payload = {
        "generated_at_epoch": time.time(),
        "source": SUPPORTED_DOMAINS_URL,
        "summary": summarize(results),
        "results": [asdict(r) for r in results],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2))

    print(f"\nWrote audit report to {args.output}")
    print(json.dumps(payload["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
