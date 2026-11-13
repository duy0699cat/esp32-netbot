# Contributing

Thanks for helping out! Bug reports, board test results, docs fixes and features are all welcome.

## Before you start

- Check existing [issues](../../issues) first. For anything bigger than a small fix, open an issue to agree on the approach before writing code.
- **Security problems go through private reporting**, not issues; see [SECURITY.md](SECURITY.md).
- By contributing you agree your work is released under the project's [MIT license](LICENSE).

## Development setup

```bash
arduino-cli config add board_manager.additional_urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
arduino-cli core install esp32:esp32@3.3.12
arduino-cli lib install ArduinoJson@7.4.3
arduino-cli compile --fqbn esp32:esp32:esp32:PartitionScheme=no_fs firmware/esp32-netbot
```

CI runs the same compile on every pull request. Provision your own board with `tools/provision.py`; the firmware has no compile-time secrets, so you never need to create a `secrets.h`.

## Guidelines

- **Never commit secrets**: tokens, Wi-Fi passwords, MACs of your own devices, private keys. CI rejects tracked `secrets.h`, `*.pem` and `*.key`, but please check your diff.
- Keep changes focused; one topic per pull request. Update the README and `CHANGELOG.md` (under *Unreleased*) when behavior changes.
- Match the existing style (2-space indent, small functions, comments that explain *why*).
- **Network and security code deserves extra care.** TLS must stay validated; anything that accepts input from Telegram must stay owner-only; keep user-supplied text out of stored formats (see `cleanText`) and HTML-escaped in messages (`esc`).
- Types used in function signatures go in `types.h`: the Arduino build generates prototypes above mid-file structs.
- Describe how you tested it: which board, what you tapped, what you saw.

## Releases

Maintainer-only; see [docs/RELEASING.md](docs/RELEASING.md). Updates are signed offline, so contributors never need (and can't have) the signing key.

## Conduct

Be kind and constructive. This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
