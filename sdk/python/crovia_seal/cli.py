#!/usr/bin/env python3
"""
Crovia Seal CLI — verify any AI seal from the command line.
Usage:  crovia-verify sl_xxx
        pip install crovia-seal && crovia-verify sl_xxx
"""
import sys
import json
from .verify import verify_seal, fetch_seal

BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
DIM = "\033[2m"
RESET = "\033[0m"
VERIFY_URL = "https://croviatrust.com/check.html"


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h"):
        print(f"""
{BOLD}crovia-verify{RESET} — Cryptographic AI provenance

{BOLD}Usage:{RESET}
  crovia-verify <seal_id>           Verify a seal
  crovia-verify --json <seal_id>    Output raw JSON
  crovia-verify --badge <seal_id>   Get embed code

{BOLD}Install:{RESET}
  pip install crovia-seal

{DIM}https://croviatrust.com{RESET}
""")
        return

    as_json = "--json" in args
    as_badge = "--badge" in args
    seal_id = [a for a in args if a.startswith("sl_")]
    if not seal_id:
        print(f"{RED}Error:{RESET} Provide a seal ID (sl_...)")
        sys.exit(1)
    seal_id = seal_id[0]

    if as_badge:
        print(f"\n{BOLD}README.md badge:{RESET}")
        print(f"[![Crovia Sealed](https://croviatrust.com/badge/seal/{seal_id}.svg)]({VERIFY_URL}?id={seal_id})\n")
        print(f"{BOLD}HTML embed:{RESET}")
        print(f'<script src="https://croviatrust.com/badge.js" data-seal="{seal_id}"></script>\n')
        return

    if as_json:
        seal = fetch_seal(seal_id)
        print(json.dumps(seal, indent=2))
        return

    print(f"\n{BOLD}Crovia Seal Verifier{RESET}\n")
    result = verify_seal(seal_id)

    if result["signature_ok"]:
        print(f"  {GREEN}✓{RESET} Ed25519 signature valid")
    else:
        print(f"  {RED}✗{RESET} Signature failed")

    seal = result.get("seal")
    if seal:
        gen = f"{seal.get('generator',{}).get('vendor','?')}/{seal.get('generator',{}).get('model','?')}"
        print(f"\n  {BOLD}{GREEN}🔒 Seal verified{RESET}")
        print(f"  {DIM}Seal ID:{RESET}    {CYAN}{seal.get('seal_id','?')}{RESET}")
        print(f"  {DIM}Generator:{RESET}  {gen}")
        print(f"  {DIM}Issued:{RESET}     {seal.get('issued_at','?')}")
        print(f"  {DIM}Issuer:{RESET}     {seal.get('issuer',{}).get('id','?')}")
        print(f"  {DIM}Verify:{RESET}     {VERIFY_URL}?id={seal_id}")
    else:
        print(f"\n  {RED}Seal not found{RESET}")

    for err in result.get("errors", []):
        print(f"  {RED}⚠ {err}{RESET}")
    print()


if __name__ == "__main__":
    main()
