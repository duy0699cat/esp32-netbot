#pragma once
// Over-the-air updates from GitHub Releases.
//
// Trust model: a release carries manifest.json (version, size, sha256 of firmware.bin) plus
// manifest.json.sig, an ECDSA P-256 / SHA-256 signature made offline with the maintainer's private
// key. The device verifies the signature against the public key compiled into the firmware, then
// checks version > current, then streams firmware.bin while hashing it, and only commits the new
// image when size and SHA-256 match the signed manifest. TLS certificates are always validated.
#include <Arduino.h>

struct OtaInfo {
  bool ok = false;      // manifest fetched and signature valid
  bool newer = false;   // manifest version > running version
  String error;
  String version;       // "1.2.3"
  String sha256;        // hex
  uint32_t size = 0;
};

OtaInfo otaCheck();
// Downloads, verifies and writes the image to the inactive slot. Does not reboot.
bool otaInstall(const OtaInfo& info, String& error, void (*progress)(int pct) = nullptr);
bool otaVersionNewer(const char* candidate, const char* current);
String otaReleaseUrl(const String& version);
