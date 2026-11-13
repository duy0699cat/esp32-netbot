#include "ota.h"
#include <HTTPClient.h>
#include <NetworkClientSecure.h>
#include <Update.h>
#include <ArduinoJson.h>
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "version.h"
#include "ota_pubkey.h"

// Change this if you fork the project.
#define OTA_REPO "duy0699cat/esp32-netbot"
#define OTA_NAME "esp32-netbot"

static const char* const RELEASES = "https://github.com/" OTA_REPO "/releases";
static const size_t MAX_FIRMWARE = 1966080;  // 1.875 MB, a bit under the 2 MB OTA slot

String otaReleaseUrl(const String& version) { return String(RELEASES) + "/tag/v" + version; }

// "1.2.3" -> true if candidate > current. Pre-release tags ("1.2.3-rc1") are never offered.
bool otaVersionNewer(const char* candidate, const char* current) {
  int a[3] = {0, 0, 0}, b[3] = {0, 0, 0};
  if (strchr(candidate, '-') || sscanf(candidate, "%d.%d.%d", &a[0], &a[1], &a[2]) != 3) return false;
  if (sscanf(current, "%d.%d.%d", &b[0], &b[1], &b[2]) != 3) return true;  // "dev" builds accept any release
  for (int i = 0; i < 3; i++) { if (a[i] != b[i]) return a[i] > b[i]; }
  return false;
}

static void configure(HTTPClient& http) {
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub redirects release assets to its CDN
  http.setUserAgent("esp32-netbot/" FW_VERSION);
  http.setTimeout(15000);
}

// Fetch a small asset (Content-Length required) into buf.
static bool fetchSmall(const String& url, uint8_t* buf, size_t cap, size_t& n, String& err) {
  NetworkClientSecure c; c.useBuiltinCACertBundle();
  HTTPClient http; configure(http);
  if (!http.begin(c, url)) { err = "bad url"; return false; }
  int code = http.GET();
  if (code != 200) { err = "HTTP " + String(code); http.end(); return false; }
  int len = http.getSize();
  if (len <= 0 || (size_t)len > cap) { err = "unexpected size"; http.end(); return false; }
  auto* s = http.getStreamPtr();
  n = 0; uint32_t last = millis();
  while (n < (size_t)len && millis() - last < 15000) {
    int av = s->available();
    if (av > 0) { n += s->readBytes(buf + n, min((size_t)av, (size_t)len - n)); last = millis(); }
    else delay(5);
  }
  http.end();
  if (n != (size_t)len) { err = "short read"; return false; }
  return true;
}

static bool verifySignature(const uint8_t* msg, size_t mlen, const uint8_t* sig, size_t slen) {
  uint8_t h[32];
  if (mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg, mlen, h) != 0) return false;
  mbedtls_pk_context pk; mbedtls_pk_init(&pk);
  int r = mbedtls_pk_parse_public_key(&pk, (const uint8_t*)OTA_PUBKEY_PEM, strlen(OTA_PUBKEY_PEM) + 1);
  if (r == 0) r = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, h, sizeof h, sig, slen);
  mbedtls_pk_free(&pk);
  return r == 0;
}

static bool isHex64(const String& s) {
  if (s.length() != 64) return false;
  for (size_t i = 0; i < 64; i++) if (!isxdigit((unsigned char)s[i])) return false;
  return true;
}

OtaInfo otaCheck() {
  OtaInfo info;
  static uint8_t man[1024], sig[160];
  size_t mn = 0, sn = 0; String err;
  if (!fetchSmall(String(RELEASES) + "/latest/download/manifest.json", man, sizeof man - 1, mn, err)) { info.error = "manifest: " + err; return info; }
  if (!fetchSmall(String(RELEASES) + "/latest/download/manifest.json.sig", sig, sizeof sig, sn, err)) { info.error = "signature file: " + err; return info; }
  if (!verifySignature(man, mn, sig, sn)) { info.error = "manifest signature is INVALID, refusing"; return info; }
  man[mn] = 0;
  JsonDocument d;
  if (deserializeJson(d, (const char*)man)) { info.error = "manifest is not valid JSON"; return info; }
  String name = d["name"] | "", ver = d["version"] | "", sha = d["sha256"] | "";
  uint32_t size = d["size"] | 0;
  if (name != OTA_NAME) { info.error = "manifest is for another project"; return info; }
  int a, b, c; char extra;
  if (sscanf(ver.c_str(), "%d.%d.%d%c", &a, &b, &c, &extra) != 3) { info.error = "bad version in manifest"; return info; }
  if (!isHex64(sha) || size < 100000 || size > MAX_FIRMWARE) { info.error = "bad size or hash in manifest"; return info; }
  info.version = ver; info.sha256 = sha; info.size = size;
  info.newer = otaVersionNewer(ver.c_str(), FW_VERSION);
  info.ok = true;
  return info;
}

bool otaInstall(const OtaInfo& info, String& error, void (*progress)(int pct)) {
  if (!info.ok || !info.newer) { error = "nothing to install"; return false; }
  NetworkClientSecure c; c.useBuiltinCACertBundle();
  HTTPClient http; configure(http);
  String url = String(RELEASES) + "/download/v" + info.version + "/firmware.bin";
  if (!http.begin(c, url)) { error = "bad url"; return false; }
  int code = http.GET();
  if (code != 200) { error = "HTTP " + String(code); http.end(); return false; }
  if (http.getSize() != (int)info.size) { error = "file size differs from the signed manifest"; http.end(); return false; }
  if (!Update.begin(info.size, U_FLASH)) { error = String("flash: ") + Update.errorString(); http.end(); return false; }

  mbedtls_sha256_context sha; mbedtls_sha256_init(&sha); mbedtls_sha256_starts(&sha, 0);
  static uint8_t buf[2048];
  auto* s = http.getStreamPtr();
  size_t total = 0; uint32_t last = millis(); int lastPct = -1;
  bool fail = false;
  while (total < info.size && !fail) {
    int av = s->available();
    if (av > 0) {
      size_t n = s->readBytes(buf, min((size_t)av, min(sizeof buf, (size_t)info.size - total)));
      if (Update.write(buf, n) != n) { error = String("flash write: ") + Update.errorString(); fail = true; break; }
      mbedtls_sha256_update(&sha, buf, n);
      total += n; last = millis();
      int pct = total * 100 / info.size;
      if (progress && pct / 10 != lastPct / 10) { lastPct = pct; progress(pct); }
    } else {
      if (millis() - last > 20000 || !http.connected()) { error = "download stalled"; fail = true; break; }
      delay(5);
    }
  }
  http.end();
  uint8_t digest[32]; mbedtls_sha256_finish(&sha, digest); mbedtls_sha256_free(&sha);
  if (fail) { Update.abort(); return false; }

  char hex[65]; for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
  if (!info.sha256.equalsIgnoreCase(hex)) { Update.abort(); error = "SHA-256 mismatch, update discarded"; return false; }
  if (!Update.end(false)) { error = String("flash finish: ") + Update.errorString(); return false; }  // also validates the image
  return true;
}
