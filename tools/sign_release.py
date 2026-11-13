#!/usr/bin/env python3
"""Sign (and optionally publish) a DRAFT release built by the Release workflow.

Run on the maintainer's machine. The private key never leaves it.

    python tools/sign_release.py v0.1.0 --key ~/.esp32-netbot/ota-signing-key.pem --publish

Checks before signing, and refuses on any mismatch:
  1. the draft's firmware.bin and manifest.json carry a valid GitHub build-provenance attestation
  2. manifest.json describes exactly this firmware.bin (name, version == tag, size, SHA-256)
  3. your private key matches the public key compiled into firmware/esp32-netbot/ota_pubkey.h
Then it signs manifest.json (ECDSA P-256 / SHA-256, DER), uploads manifest.json.sig, and publishes.
Requires: gh (logged in, with access to the repo) and openssl on PATH.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = "duy0699cat/esp32-netbot"
ROOT = pathlib.Path(__file__).resolve().parent.parent
PUBKEY_HEADER = ROOT / "firmware" / "esp32-netbot" / "ota_pubkey.h"


def find(tool, extra=()):
    p = shutil.which(tool)
    if p:
        return p
    for e in extra:
        if pathlib.Path(e).exists():
            return e
    sys.exit(f"{tool} not found on PATH")


GH = find("gh", [r"C:\Program Files\GitHub CLI\gh.exe"])
OPENSSL = find("openssl", [r"C:\Program Files\Git\mingw64\bin\openssl.exe", r"C:\Program Files\Git\usr\bin\openssl.exe"])


def run(cmd, **kw):
    print("$", " ".join(str(c) for c in cmd))
    return subprocess.run([str(c) for c in cmd], check=True, text=True, **kw)


def firmware_pubkey_lines():
    src = PUBKEY_HEADER.read_text()
    lines = re.findall(r'"([^"]*?)\\n"', src)
    return [l.strip() for l in lines if l.strip()]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tag", help="release tag, e.g. v0.1.0")
    ap.add_argument("--key", required=True, help="path to the ECDSA P-256 private key (PEM)")
    ap.add_argument("--repo", default=REPO)
    ap.add_argument("--publish", action="store_true", help="publish the release after signing")
    a = ap.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+", a.tag):
        sys.exit("tag must look like v1.2.3")

    # 3. key must match the key the firmware trusts
    derived = subprocess.run([OPENSSL, "ec", "-in", a.key, "-pubout"], check=True, capture_output=True, text=True).stdout
    derived_lines = [l.strip() for l in derived.splitlines() if l.strip()]
    if derived_lines != firmware_pubkey_lines():
        sys.exit("REFUSING: this private key does not match ota_pubkey.h; devices would reject the update")
    print("ok: signing key matches the public key in the firmware")

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="netbot-sign-"))
    try:
        run([GH, "release", "download", a.tag, "--repo", a.repo, "--dir", tmp, "-p", "firmware.bin", "-p", "manifest.json", "-p", "esp32-netbot-factory.bin"])
        fw, man = tmp / "firmware.bin", tmp / "manifest.json"

        # 1. provenance
        for f in (fw, man, tmp / "esp32-netbot-factory.bin"):
            run([GH, "attestation", "verify", f, "--repo", a.repo])

        # 2. manifest describes this binary
        m = json.loads(man.read_text())
        data = fw.read_bytes()
        problems = []
        if m.get("name") != "esp32-netbot": problems.append("name")
        if m.get("version") != a.tag[1:]: problems.append("version != tag")
        if m.get("size") != len(data): problems.append("size")
        if m.get("sha256") != hashlib.sha256(data).hexdigest(): problems.append("sha256")
        if problems:
            sys.exit("REFUSING: manifest does not match firmware.bin: " + ", ".join(problems))
        print(f"ok: manifest matches firmware.bin ({len(data)} bytes, v{m['version']})")

        sig = tmp / "manifest.json.sig"
        run([OPENSSL, "dgst", "-sha256", "-sign", a.key, "-out", sig, man])
        pub = tmp / "pub.pem"
        pub.write_text(derived)
        run([OPENSSL, "dgst", "-sha256", "-verify", pub, "-signature", sig, man])

        run([GH, "release", "upload", a.tag, sig, "--repo", a.repo, "--clobber"])

        if a.publish:
            body = subprocess.run([GH, "release", "view", a.tag, "--repo", a.repo, "--json", "body", "--jq", ".body"],
                                  check=True, capture_output=True, text=True).stdout
            body = "\n".join(l for l in body.splitlines() if not l.startswith("Draft: awaiting"))
            notes = tmp / "notes.md"
            notes.write_text(body.strip() + "\n")
            run([GH, "release", "edit", a.tag, "--repo", a.repo, "--draft=false", "--latest", "--notes-file", notes])
            print(f"published {a.tag}")
        else:
            print("signed and uploaded; publish with:  gh release edit", a.tag, "--draft=false --latest")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
