# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting:
[Report a vulnerability](../../security/advisories/new). I'll acknowledge within a few days, and credit you in the advisory if you'd like.

Only the **latest release** receives fixes.

## What this device protects, and how

The ESP32 holds three things worth protecting: your **Telegram bot token**, your **Wi-Fi passwords**, and the ability to **send traffic onto your LAN** (Wake-on-LAN, scans). It can't touch anything beyond that.

| Risk | Mitigation |
| --- | --- |
| Someone else controls the bot | The bot answers only the **owner chat**. A new bot is claimed with a random 6-digit **PIN shown only on the USB serial console**; 5 wrong guesses lock claiming for 15 minutes. Everyone else is silently ignored. |
| Secrets leaking through the firmware or repo | **No secret is compiled in.** Token, Wi-Fi and PIN are written to flash over USB. `secrets.h` and key files are git-ignored, and CI fails if they are ever tracked. |
| Secrets in chat history | Messages containing a Wi-Fi password or the claim PIN are **deleted** from the chat right after use. |
| Man-in-the-middle on your LAN | Every TLS connection **validates the certificate chain** against the built-in CA bundle (the clock is synced by NTP first). There is no "insecure" fallback. |
| Malicious or tampered firmware update | Updates must carry an **ECDSA P-256 signature** over a manifest, verified against a public key compiled into the firmware. The manifest binds the version, size and SHA-256 of the binary. The device refuses downgrades and pre-releases, and only commits an image after the hash matches. |
| Compromised GitHub account or CI | The **signing key is never on GitHub**. Releases are built in CI (with build-provenance attestations), but signed offline by the maintainer. An attacker who controls the repo or workflow can't produce an update the device will accept. |
| A bad update bricks the device | The bootloader's **app rollback** is enabled: a new image must reach Telegram within minutes or the previous firmware is restored. |
| Scanning abuse | Scans and Wake-on-LAN only run on the owner's request, or the periodic ARP sweep of the device's own /24. |

## Known limitations

- **Physical access is game over.** Flash encryption and secure boot are not enabled, so someone with the board and a USB cable can read the token and Wi-Fi passwords or flash other firmware. If a device is lost or stolen: revoke the token in @BotFather (`/revoke`) and change your Wi-Fi password.
- The bot token grants control of the bot. Telegram bot chats are not end-to-end encrypted.
- Your LAN's ARP is unauthenticated; a hostile device on your network can spoof presence results.
- Update authenticity depends on the maintainer's offline signing key. If it is ever lost or leaked, a new key requires a USB re-flash of existing devices, and an advisory will say so.

## Verifying what you run

Release artifacts have GitHub build-provenance attestations (`gh attestation verify <file> --repo duy0699cat/esp32-netbot`) and a `SHA256SUMS` file. The source builds with the commands in the README; the public key the firmware trusts is in [`firmware/esp32-netbot/ota_pubkey.h`](firmware/esp32-netbot/ota_pubkey.h).
