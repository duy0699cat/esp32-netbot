#!/usr/bin/env python3
"""Provision an esp32-netbot over USB serial: bot token, Wi-Fi network(s), and show the claim PIN.

Secrets are asked for with hidden input (getpass), so they never land in your shell history.
Nothing is sent anywhere except to the ESP32 on the serial port you choose.

    pip install pyserial
    python tools/provision.py --port COM5
    python tools/provision.py --port /dev/ttyUSB0 --wifi-ssid "My Network"
"""
import argparse
import getpass
import sys
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial is required:  pip install pyserial")


def send(ser, line, show=None, timeout=25):
    """Send one console line and wait for its OK/ERR reply. `show` is printed instead of `line`."""
    ser.reset_input_buffer()
    ser.write((line + "\n").encode())
    print(">", show if show is not None else line)
    end = time.time() + timeout
    buf = b""
    while time.time() < end:
        chunk = ser.read(256)
        if chunk:
            buf += chunk
            text = buf.decode(errors="replace")
            for ln in text.splitlines():
                if ln.startswith(("OK", "ERR")):
                    print("<", ln)
                    return ln.startswith("OK")
    print("< (no reply: the device may be busy, try again)")
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="serial port, e.g. COM5 or /dev/ttyUSB0")
    ap.add_argument("--wifi-ssid", help="2.4 GHz network name (asked for if omitted)")
    ap.add_argument("--skip-token", action="store_true", help="don't set the bot token")
    ap.add_argument("--skip-wifi", action="store_true", help="don't add a Wi-Fi network")
    a = ap.parse_args()

    ser = serial.Serial(a.port, 115200, timeout=0.2)
    time.sleep(2.5)  # opening the port may reset the board; let it boot

    if not a.skip_token:
        token = getpass.getpass("Bot token from @BotFather (hidden): ").strip()
        if token:
            send(ser, f"token {token}", show="token ********")
    if not a.skip_wifi:
        ssid = a.wifi_ssid or input("Wi-Fi name (SSID, 2.4 GHz): ").strip()
        if ssid:
            pw = getpass.getpass("Wi-Fi password (hidden, empty for an open network): ")
            send(ssid and f'wifi add "{ssid}" {pw}', show=f'wifi add "{ssid}" ********')
    print()
    ser.write(b"pin show\n")
    time.sleep(1)
    print(ser.read(2000).decode(errors="replace").strip())
    print("\nNow open your bot in Telegram and send  /claim <PIN>  to become its owner.")


if __name__ == "__main__":
    main()
