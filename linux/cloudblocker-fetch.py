#!/usr/bin/env python3
"""
Cloud Blocker (Linux) - provider IP-range fetcher/parser.

Usage: cloudblocker-fetch.py <aws|gcp|azure> [url]

Prints one IPv4 CIDR per line. Uses only the Python standard library so it runs
on a stock Ubuntu install. Retries, and auto-resolves the (versioned) Azure
Service Tags download URL.
"""
import json
import re
import ssl
import sys
import time
import urllib.request

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

DEFAULT_URLS = {
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "gcp": "https://www.gstatic.com/ipranges/cloud.json",
}

AZURE_CONFIRM = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"


def fetch(url, timeout=180, retries=3):
    last = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = resp.read()
            if len(data) < 32:
                raise RuntimeError("response too small (%d bytes)" % len(data))
            return data.decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            last = exc
            sys.stderr.write("fetch attempt %d/%d failed: %s\n" % (attempt, retries, exc))
            time.sleep(2 * attempt)
    raise RuntimeError("failed to fetch %s: %s" % (url, last))


def resolve_azure():
    page = fetch(AZURE_CONFIRM, timeout=60, retries=2)
    m = re.search(r'href="(https://download\.microsoft\.com/download/[^"]+\.json)"', page)
    if not m:
        raise RuntimeError("could not resolve Azure download URL")
    return m.group(1)


def parse(provider, data):
    if provider == "aws":
        return [p.get("ip_prefix") for p in data.get("prefixes", []) if p.get("ip_prefix")]
    if provider == "gcp":
        return [p.get("ipv4Prefix") for p in data.get("prefixes", []) if p.get("ipv4Prefix")]
    if provider == "azure":
        out = []
        for v in data.get("values", []):
            for pfx in v.get("properties", {}).get("addressPrefixes", []) or []:
                out.append(pfx)
        return out
    raise RuntimeError("unknown provider: %s" % provider)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: cloudblocker-fetch.py <aws|gcp|azure> [url]\n")
        return 2
    provider = sys.argv[1].lower()
    url = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else DEFAULT_URLS.get(provider, "")
    if provider == "azure" and not url:
        url = resolve_azure()
    if not url:
        sys.stderr.write("no URL configured for provider '%s'\n" % provider)
        return 1
    data = json.loads(fetch(url))
    for cidr in parse(provider, data):
        if cidr:
            sys.stdout.write(str(cidr).strip() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
