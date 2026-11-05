"""Run the Gated Browser as a local stdio MCP server for one person.

    python -m oac.browser --person person:me --signer-metadata signer.json \
        --consent-url "https://signer.example/consent?r={id}" [--allow-http 127.0.0.1] [--block linkedin.com]

signer.json is the signer's issuer metadata (spec 3.5): the keys whose Consents this browser accepts. The executor
key is created fresh for each run unless --executor-key points to a 32-byte seed file (keep it private)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from oac.discovery import keyset_from
from oac.jws import ed25519_from_seed, generate
from oac.browser import Guard, build_server


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m oac.browser", description="Gated Browser: an MCP browser that stops before every final click.")
    ap.add_argument("--person", required=True, help="the one person this local browser acts for")
    ap.add_argument("--signer-metadata", required=True, type=Path, help="the signer's issuer metadata JSON")
    ap.add_argument("--consent-url", required=True, help="approval page URL; {id} is replaced by the preview id")
    ap.add_argument("--executor", default="https://localhost/oac-browser", help="this browser's OAC executor id")
    ap.add_argument("--executor-key", type=Path, help="file with a 32-byte Ed25519 seed for signing receipts")
    ap.add_argument("--allow-http", action="append", default=[], help="host allowed over plain http (testing)")
    ap.add_argument("--block", action="append", default=[], help="site never opened (and its subdomains)")
    ap.add_argument("--headed", action="store_true", help="show the browser window")
    a = ap.parse_args()
    meta = json.loads(a.signer_metadata.read_text())
    key = ed25519_from_seed(a.executor_key.read_bytes()[:32]) if a.executor_key else generate()
    server, _, _ = build_server(
        executor=a.executor, key=key, signers=keyset_from([(meta["issuer"], meta)]),
        consent_url=lambda p: a.consent_url.replace("{id}", p["id"]), person=lambda ctx: a.person,
        guard=Guard(allow_http=a.allow_http, blocked_sites=a.block), headless=not a.headed)
    server.run()


if __name__ == "__main__":
    main()
