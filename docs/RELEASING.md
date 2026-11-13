# Releasing

Maintainer notes. The flow keeps the **update-signing private key off GitHub**: CI builds, a human signs.

```
tag vX.Y.Z  ->  CI builds + attests  ->  DRAFT release  ->  tools/sign_release.py  ->  published
```

## One-time: create the signing key

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ota-signing-key.pem   # keep OUTSIDE the repo
openssl ec -in ota-signing-key.pem -pubout                                   # paste into firmware/esp32-netbot/ota_pubkey.h
```

Store the private key somewhere private and **back it up** (password manager or encrypted drive). Losing it means existing devices can't be updated over the air; leaking it lets someone push firmware to every device. `*.pem` is git-ignored.

Forking? Do this with your own key, replace `ota_pubkey.h`, and change `OTA_REPO` in `firmware/esp32-netbot/ota.cpp`.

## Cutting a release

1. Update `FW_VERSION` in `firmware/esp32-netbot/version.h` and move the *Unreleased* notes in `CHANGELOG.md` under the new version.
2. Merge to `main` once CI is green.
3. Tag and push (the tag must equal `v` + `FW_VERSION`):
   ```bash
   git tag -s vX.Y.Z -m "vX.Y.Z"    # or: git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
4. The **Release** workflow builds `firmware.bin` (OTA image), `esp32-netbot-factory.bin` (full flash image), `manifest.json` and `SHA256SUMS`, attests them, and creates a **draft** release.
5. Sign and publish from your machine (needs `gh` and `openssl`):
   ```bash
   python tools/sign_release.py vX.Y.Z --key /path/to/ota-signing-key.pem --publish
   ```
   The script downloads the draft's assets, verifies the build-provenance attestation, checks that the manifest matches the binary, signs `manifest.json`, uploads `manifest.json.sig`, and publishes.
6. Sanity check on a device: `/update` in Telegram, or `update check` on the serial console.

Devices only look at the **latest published, non-pre-release** release, and only trust a manifest whose signature verifies. A draft (or a release without `manifest.json.sig`) is never installed.

## If the key is compromised or lost

Devices will keep trusting the old public key. Publish a security advisory, ship a new firmware containing the new public key (signed with the old key if you still have it; otherwise users must re-flash over USB), and revoke the old key's use. Never reuse a leaked key.
