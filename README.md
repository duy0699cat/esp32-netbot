# esp32-netbot

A Telegram bot that runs on a ~$5 ESP32 and manages your home network from your phone: **scan** for devices, **ping** them, send **Wake-on-LAN**, and get **alerts** when something new joins. Everything is a tap on an inline button, and it works from anywhere because the bot polls Telegram outbound (no port forwarding, no cloud service of your own).

- 📋 **Devices**: save machines by name; ⚡ Wake / 📡 Ping / rename / set IP / delete, all from buttons
- 🔍 **Scan**: ARP sweep of your /24 with MAC vendor hints; tap ➕ to save a device
- 📡 **Smart ping**: ICMP, then common TCP ports, then ARP, so it can tell "firewall blocks ping" from "really off"
- 🔔 **Alerts**: new unknown device on the network, and online/offline for devices you watch
- 📶 **Wi-Fi list**: remembers several networks, joins the strongest known one, switches when a better one appears
- ⬆️ **Signed OTA updates** from GitHub Releases, with automatic rollback if an update can't get back online
- 🔒 **No secrets in the firmware**: token, Wi-Fi and PIN live in the chip's flash; the release image is generic

Only the owner's Telegram chat can control it. The device talks to `api.telegram.org`, `github.com` (update checks) and NTP, nothing else. No telemetry.

## Hardware

Any classic **ESP32** dev board with 4 MB flash (tested on an ESP32-D0WD-V3 with a CH340 USB chip). Your Wi-Fi must offer a **2.4 GHz** network; the ESP32 cannot see 5 GHz. The LAN scan assumes an IPv4 /24 subnet.

## Quick start

1. **Create a bot** with [@BotFather](https://t.me/BotFather) and keep the token.
2. **Download** `esp32-netbot-factory.bin` and `SHA256SUMS` from the [latest release](../../releases/latest) and verify it (see [Verifying a release](#verifying-a-release)).
3. **Flash** it (needs [`esptool`](https://github.com/espressif/esptool): `pip install esptool`):
   ```bash
   esptool --chip esp32 --port COM5 write_flash 0x0 esp32-netbot-factory.bin
   ```
4. **Provision** it over USB (secrets are typed with hidden input and stored in the chip, never in a file):
   ```bash
   pip install pyserial
   python tools/provision.py --port COM5
   ```
   It asks for the bot token and your Wi-Fi, then prints a **claim PIN**.
5. In Telegram, open your bot and send `/claim <PIN>`. You're the owner; send `/menu`.

If the board has no network yet, it waits for you; the serial console (`115200` baud, type `help`) always works for diagnostics.

## Using it

Open `/menu` and tap. Typed commands also work:

| Command | What it does |
| --- | --- |
| `/menu` | Home screen with buttons |
| `/devices` | Saved devices with Wake / Ping / settings buttons |
| `/scan` | Find devices on the LAN; ➕ saves one |
| `/add <name> <mac or ip> [ip]` | Save a device (an IP makes the bot look up the MAC) |
| `/edit <name> name\|mac\|ip <value>` | Change a saved device (`-` clears the IP) |
| `/del <name>` | Remove a device |
| `/wake <device or mac>` | Send a Wake-on-LAN magic packet |
| `/ping <device, ip or hostname>` | Smart ping |
| `/wifi` | Manage known networks; `add`, `del`, `switch` also work typed |
| `/alerts` | New-device alerts, scan interval, daily update check |
| `/update` | Check GitHub for a newer signed release |
| `/status` | Firmware version, Wi-Fi, IP, uptime |

Wake-on-LAN also needs to be enabled on the target machine (BIOS/UEFI and the network adapter's "Wake on Magic Packet").

### Serial console

`status`, `token`, `wifi list|add|del`, `pin show|new`, `owner reset`, `update check|install`, `scan`, `factory-reset yes`, `reboot`. Type `help` for details.

## Updates

The bot checks the latest GitHub Release once a day (you can turn that off) and offers an **Install** button. Nothing is installed without your tap. Before flashing, the device verifies an ECDSA signature on the release manifest, checks the version is newer, and checks the size and SHA-256 of the firmware against that signed manifest. TLS certificates are validated throughout. If the new firmware can't reach Telegram within a few minutes, the bootloader rolls back to the previous one. Details in [SECURITY.md](SECURITY.md).

## Verifying a release

Releases are built by GitHub Actions and carry build-provenance attestations:

```bash
gh attestation verify esp32-netbot-factory.bin --repo duy0699cat/esp32-netbot
sha256sum -c SHA256SUMS --ignore-missing
```

## Build from source

Needs [`arduino-cli`](https://arduino.github.io/arduino-cli/), the ESP32 core `3.3.12` and `ArduinoJson 7.4.3`:

```bash
arduino-cli config add board_manager.additional_urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
arduino-cli core install esp32:esp32@3.3.12
arduino-cli lib install ArduinoJson@7.4.3
arduino-cli compile --fqbn esp32:esp32:esp32:PartitionScheme=no_fs firmware/esp32-netbot
arduino-cli upload  --fqbn esp32:esp32:esp32:PartitionScheme=no_fs -p COM5 firmware/esp32-netbot
```

The `no_fs` partition scheme (two 2 MB app slots) is required for OTA. **Forking?** Generate your own update-signing key and change `OTA_REPO`; see [docs/RELEASING.md](docs/RELEASING.md).

### MAC vendor names (optional)

`/scan` labels random-MAC phones out of the box. For brand names, generate a table from the public IEEE registry and rebuild:

```bash
python tools/gen_oui.py path/to/oui.csv firmware/esp32-netbot/oui_table.h
```

## Limitations

- 2.4 GHz Wi-Fi only; IPv4 /24 LANs only.
- Presence is ARP-based: devices that deep-sleep their Wi-Fi may look offline. Offline needs two missed scans plus a re-check.
- One owner chat. Group chats and multiple users are not supported.
- Tested on one board type; reports from other ESP32 boards are welcome.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please report security problems privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Uses [ArduinoJson](https://arduinojson.org/) (MIT) and the [Arduino-ESP32](https://github.com/espressif/arduino-esp32) core (LGPL-2.1).
