# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-14

First public release.

### Added
- Telegram bot with a tap-button interface: devices, scan, Wi-Fi, alerts, status.
- Network scan (ARP), smart ping (ICMP, then TCP ports, then ARP) and Wake-on-LAN.
- Saved devices (add, rename, set IP, delete) stored in flash.
- Presence alerts for watched devices and one-time alerts for new unknown devices.
- Multiple saved Wi-Fi networks with automatic join and switching to a stronger network.
- Signed over-the-air updates from GitHub Releases with downgrade protection and automatic rollback.
- USB serial console and `tools/provision.py` for setting the bot token, Wi-Fi and claim PIN.

### Security
- No secrets compiled into the firmware; configuration lives in NVS flash.
- All TLS connections validate certificates (NTP-synced clock).
- Owner claimed with a console-only PIN, with lockout after repeated wrong guesses.
- Release images are built in CI with provenance attestations and signed offline.

[Unreleased]: https://github.com/duy0699cat/esp32-netbot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/duy0699cat/esp32-netbot/releases/tag/v0.1.0
