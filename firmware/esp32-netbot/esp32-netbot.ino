// esp32-netbot: a Telegram bot on an ESP32 for your home network.
// Tap-button UI, device list + Wi-Fi list (stored in flash), ARP scan, ICMP/TCP/ARP ping, Wake-on-LAN,
// presence + new-device alerts, auto-switching between known Wi-Fi networks, signed OTA updates.
//
// No secrets are compiled in: the bot token, Wi-Fi networks and claim PIN are provisioned over USB serial
// (see README / tools/provision.py) and kept in NVS flash.
#include <WiFi.h>
#include <NetworkClientSecure.h>
#include <WiFiUdp.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <vector>
#include <algorithm>
#include <time.h>
#include "esp_ota_ops.h"
#include "esp_random.h"
#include "ping/ping_sock.h"
#include "version.h"
#include "oui_table.h"
#include "types.h"
#include "ota.h"
extern "C" {
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
}

struct Net { String ssid, pass; };
struct Dev {
  String name, mac, ip;      // persisted
  bool watch = false;        // persisted: send online/offline alerts
  String lastIp;             // runtime: IP seen in the last sweep
  bool online = false;
  uint8_t missed = 0;
};
struct Host { IPAddress ip; uint8_t mac[6]; };

Preferences prefs;
std::vector<Net> nets;
std::vector<Dev> devs;
std::vector<String> seen;          // every MAC we've ever noticed (new-device alerts fire once)
std::vector<Host> lastHosts;       // result of the most recent sweep
std::vector<String> scannedSsids;  // result of the last "visible networks" scan
NetworkClientSecure tls;
String botToken, claimPin, curSsid, conLine, lastOfferedVer;
long long lastUpdate = 0, owner = 0;
uint32_t lastCheck = 0, nextSweep = 0, nextUpdCheck = 0, claimLockUntil = 0, sweepMin = 5;
uint8_t claimFails = 0;
bool alertsOn = true, updCheckOn = true, presenceReady = false;
bool timeOk = false, tgInited = false, tgOk = false, rollbackCleared = false;

enum PKind { P_NONE, P_NAME_NEW, P_RENAME, P_SETIP, P_WIFI_SSID, P_WIFI_PASS };
struct Pending { PKind kind = P_NONE; String a, b; uint32_t t = 0; } pending;

// Keep the new image "pending verify" until we've proven Wi-Fi + Telegram work; if it resets first,
// the bootloader rolls back to the previous firmware.
extern "C" bool verifyRollbackLater() { return true; }

void consoleTick();
void waitMs(uint32_t ms) { uint32_t t0 = millis(); while (millis() - t0 < ms) { consoleTick(); delay(10); } }

// ================= helpers =================
String esc(String s) { s.replace("&", "&amp;"); s.replace("<", "&lt;"); s.replace(">", "&gt;"); return s; }

std::vector<String> splitStr(const String& s, char sep) {
  std::vector<String> v; int st = 0;
  while (true) {
    int i = s.indexOf(sep, st);
    if (i < 0) { v.push_back(s.substring(st)); break; }
    v.push_back(s.substring(st, i)); st = i + 1;
  }
  return v;
}

// split on spaces; "double quotes" keep spaces together
std::vector<String> tokens(const String& s) {
  std::vector<String> v; String cur; bool q = false, has = false;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"') { q = !q; has = true; }
    else if (c == ' ' && !q) { if (has) { v.push_back(cur); cur = ""; has = false; } }
    else { cur += c; has = true; }
  }
  if (has) v.push_back(cur);
  return v;
}

bool parseMac(const String& s, uint8_t* out) {
  unsigned v[6]; char t;
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x%c", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &t) != 6 &&
      sscanf(s.c_str(), "%x-%x-%x-%x-%x-%x%c", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &t) != 6) return false;
  for (int i = 0; i < 6; i++) { if (v[i] > 255) return false; out[i] = v[i]; }
  return true;
}
String macStr(const uint8_t* m) {
  char b[18]; snprintf(b, sizeof b, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]); return b;
}
bool isIp(const String& s) { IPAddress a; return a.fromString(s); }
String keyOf(const String& mac) { String k = mac; k.replace(":", ""); k.toUpperCase(); return k; }       // callback-safe id
String macFromKey(const String& k) {
  if (k.length() != 12) return "";
  String m; for (int i = 0; i < 12; i += 2) { if (i) m += ":"; m += k.substring(i, i + 2); } return m;
}
bool cleanText(const String& s, size_t maxLen) {  // no separators / control chars that would corrupt storage
  if (!s.length() || s.length() > maxLen) return false;
  for (size_t i = 0; i < s.length(); i++) { char c = s[i]; if (c == '|' || c == '\t' || c == '\n' || c == '\r' || c == ',') return false; }
  return true;
}

String vendorOf(const uint8_t* m) {
  if (m[0] & 0x02) return "private/random MAC";  // locally administered: phones rotate these
  uint32_t p = ((uint32_t)m[0] << 16) | (m[1] << 8) | m[2];
  size_t lo = 0, hi = OUI_COUNT;
  while (lo < hi) {
    size_t mid = (lo + hi) / 2; uint32_t e = OUI_TABLE[mid] & 0xFFFFFF;
    if (e == p) return OUI_VENDORS[OUI_TABLE[mid] >> 24];
    if (e < p) lo = mid + 1; else hi = mid;
  }
  return "";
}

// ================= storage =================
void saveNets() { String s; for (auto& n : nets) s += n.ssid + "\t" + n.pass + "\n"; prefs.putString("wifis", s); }
void saveDevs() { String s; for (auto& d : devs) s += d.name + "|" + d.mac + "|" + d.ip + "|" + (d.watch ? "1" : "0") + "\n"; prefs.putString("devs", s); }
void saveSeen() {
  while (seen.size() > 80) seen.erase(seen.begin());
  String s; for (auto& m : seen) s += m + ","; prefs.putString("seen", s);
}
void saveSettings() { prefs.putBool("alerts", alertsOn); prefs.putUInt("sweepMin", sweepMin); prefs.putBool("updCheck", updCheckOn); }
String newPin() { char b[8]; snprintf(b, sizeof b, "%06u", (unsigned)(100000 + esp_random() % 900000)); return b; }

void loadAll() {
  prefs.begin("bot", false);
  owner = prefs.getLong64("owner", 0);
  alertsOn = prefs.getBool("alerts", true);
  updCheckOn = prefs.getBool("updCheck", true);
  sweepMin = prefs.getUInt("sweepMin", 5);
  botToken = prefs.getString("token", "");
  claimPin = prefs.getString("pin", "");
  if (!claimPin.length()) { claimPin = newPin(); prefs.putString("pin", claimPin); }
  for (auto& l : splitStr(prefs.getString("wifis", ""), '\n')) {
    auto f = splitStr(l, '\t'); if (f.size() >= 2 && f[0].length()) nets.push_back({f[0], f[1]});
  }
  for (auto& l : splitStr(prefs.getString("devs", ""), '\n')) {
    auto f = splitStr(l, '|');
    if (f.size() >= 3 && f[0].length()) { Dev d; d.name = f[0]; d.mac = f[1]; d.ip = f[2]; d.watch = f.size() > 3 && f[3] == "1"; devs.push_back(d); }
  }
  for (auto& m : splitStr(prefs.getString("seen", ""), ',')) if (m.length() == 17) seen.push_back(m);
}

Dev* findDev(const String& name) { for (auto& d : devs) if (d.name.equalsIgnoreCase(name)) return &d; return nullptr; }
Dev* devByKey(const String& key) { for (auto& d : devs) if (keyOf(d.mac) == key) return &d; return nullptr; }
Net* findNet(const String& ssid) { for (auto& n : nets) if (n.ssid == ssid) return &n; return nullptr; }
String devByMac(const String& mac) { for (auto& d : devs) if (d.mac.equalsIgnoreCase(mac)) return d.name; return ""; }
String bestIp(const Dev& d) { return d.ip.length() ? d.ip : d.lastIp; }
bool inSeen(const String& mac) { for (auto& m : seen) if (m == mac) return true; return false; }

// ================= Telegram layer =================
String api(const String& m) { return "https://api.telegram.org/bot" + botToken + "/" + m; }

// One keep-alive TLS connection (certificate-validated) is reused between calls; if it went stale we reconnect once.
int tgCall(const String& method, const String& body, String* out = nullptr, uint32_t timeoutMs = 8000) {
  if (!botToken.length() || !timeOk) return -1;
  int code = -1;
  for (int attempt = 0; attempt < 2; attempt++) {
    HTTPClient http; http.setReuse(true); http.setTimeout(timeoutMs);
    http.begin(tls, api(method));
    if (body.length()) { http.addHeader("Content-Type", "application/json"); code = http.POST(body); }
    else code = http.GET();
    if (code > 0) { if (out) *out = http.getString(); http.end(); break; }
    http.end(); tls.stop();
  }
  tgOk = code == 200;
  if (code != 200 && code != 400) Serial.printf("telegram %s -> %d\n", method.substring(0, method.indexOf('?')).c_str(), code);
  return code;
}
void tgPost(const char* method, JsonDocument& d) { String b; serializeJson(d, b); tgCall(method, b); }

void sendOne(long long chat, const String& text, Kb* kb) {
  JsonDocument d; d["chat_id"] = chat; d["text"] = text; d["parse_mode"] = "HTML"; d["link_preview_options"]["is_disabled"] = true;
  if (kb) d["reply_markup"]["inline_keyboard"] = kb->doc["inline_keyboard"];
  tgPost("sendMessage", d);
}
void sendMsg(long long chat, String text, Kb* kb = nullptr) {
  while (text.length() > 3800) {
    int cut = text.lastIndexOf('\n', 3800); if (cut <= 0) cut = 3800;
    sendOne(chat, text.substring(0, cut), nullptr); text = text.substring(cut);
  }
  sendOne(chat, text, kb);
}
void editMsg(long long chat, long long id, const String& text, Kb* kb) {
  JsonDocument d; d["chat_id"] = chat; d["message_id"] = id; d["text"] = text; d["parse_mode"] = "HTML";
  if (kb) d["reply_markup"]["inline_keyboard"] = kb->doc["inline_keyboard"];
  tgPost("editMessageText", d);
}
void show(long long chat, long long msgId, const String& text, Kb* kb) {
  if (msgId) editMsg(chat, msgId, text, kb); else sendMsg(chat, text, kb);
}
void answerCb(const String& id, const String& text = "") {
  JsonDocument d; d["callback_query_id"] = id; if (text.length()) d["text"] = text; tgPost("answerCallbackQuery", d);
}
void deleteMsg(long long chat, long long id) {
  JsonDocument d; d["chat_id"] = chat; d["message_id"] = id; tgPost("deleteMessage", d);
}
void setCommands() {
  JsonDocument d; JsonArray a = d["commands"].to<JsonArray>();
  const char* c[][2] = {{"menu", "Open the button menu"}, {"devices", "Saved devices"}, {"scan", "Scan the network"},
                        {"wifi", "Wi-Fi networks"}, {"update", "Check for firmware updates"}, {"status", "ESP32 status"}, {"help", "Command list"}};
  for (auto& x : c) { JsonObject o = a.add<JsonObject>(); o["command"] = x[0]; o["description"] = x[1]; }
  tgPost("setMyCommands", d);
}

// ================= network tools =================
bool arpProbe(int h, uint8_t* macOut) {
  IPAddress me = WiFi.localIP();
  ip4_addr_t ip; IP4_ADDR(&ip, me[0], me[1], me[2], h);
  // lwIP is built with thread-safety checks: etharp_* must run under the TCP/IP core lock
  LOCK_TCPIP_CORE();
  netif* nif = netif_default;
  if (nif) etharp_request(nif, &ip);
  UNLOCK_TCPIP_CORE();
  if (!nif) return false;
  delay(80);
  eth_addr* m = nullptr; const ip4_addr_t* r = nullptr;
  bool ok = false;
  LOCK_TCPIP_CORE();
  if (etharp_find_addr(nif, &ip, &m, &r) >= 0 && m) { memcpy(macOut, m->addr, 6); ok = true; }
  UNLOCK_TCPIP_CORE();
  return ok;
}

// Sweep the /24. If wantMac is set, stop at the first host with that MAC.
void sweep(std::vector<Host>& out, const uint8_t* wantMac = nullptr) {
  IPAddress me = WiFi.localIP();
  for (int h = 1; h < 255; h++) {
    if (h == me[3]) continue;
    Host x; x.ip = IPAddress(me[0], me[1], me[2], h);
    if (arpProbe(h, x.mac)) {
      out.push_back(x);
      if (wantMac && !memcmp(wantMac, x.mac, 6)) return;
    }
  }
}

bool ipForMac(const String& mac, IPAddress& ip) {
  uint8_t m[6]; if (!parseMac(mac, m)) return false;
  std::vector<Host> hs; sweep(hs, m);
  for (auto& h : hs) if (!memcmp(h.mac, m, 6)) { ip = h.ip; return true; }
  return false;
}

String wake(const String& target) {
  String mac = target;
  if (Dev* d = findDev(target)) mac = d->mac;
  uint8_t m[6];
  if (!parseMac(mac, m)) return "Unknown device. Use a saved name (/devices) or a MAC.";
  uint8_t pkt[102]; memset(pkt, 0xFF, 6);
  for (int i = 0; i < 16; i++) memcpy(pkt + 6 + i * 6, m, 6);
  WiFiUDP udp; IPAddress bc = WiFi.localIP() | ~WiFi.subnetMask();
  for (uint16_t p : {9, 7}) { udp.beginPacket(bc, p); udp.write(pkt, sizeof pkt); udp.endPacket(); }
  udp.beginPacket(IPAddress(255, 255, 255, 255), 9); udp.write(pkt, sizeof pkt); udp.endPacket();
  return "⚡ Magic packet sent to <code>" + macStr(m) + "</code>" + (findDev(target) ? " (" + esc(target) + ")" : "");
}

bool icmpPing(IPAddress ip, PingStats& st) {
  esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
  ip_addr_t target; IP_ADDR4(&target, ip[0], ip[1], ip[2], ip[3]);
  cfg.target_addr = target; cfg.count = 4; cfg.interval_ms = 300; cfg.timeout_ms = 1000;
  esp_ping_callbacks_t cbs = {};
  cbs.cb_args = &st;
  cbs.on_ping_success = [](esp_ping_handle_t h, void* a) {
    auto* s = (PingStats*)a; uint32_t t = 0;
    esp_ping_get_profile(h, ESP_PING_PROF_TIMEGAP, &t, sizeof t);
    s->ok++; s->sum += t; if (t < s->mn) s->mn = t; if (t > s->mx) s->mx = t;
  };
  cbs.on_ping_timeout = [](esp_ping_handle_t, void*) {};
  cbs.on_ping_end = [](esp_ping_handle_t, void* a) { ((PingStats*)a)->done = true; };
  esp_ping_handle_t h;
  if (esp_ping_new_session(&cfg, &cbs, &h) != ESP_OK) return false;
  esp_ping_start(h);
  uint32_t t0 = millis();
  while (!st.done && millis() - t0 < 8000) delay(20);
  esp_ping_stop(h); esp_ping_delete_session(h);
  return st.ok > 0;
}

// Windows & many phones drop ICMP; an open TCP port still proves the host is alive.
int tcpProbe(IPAddress ip) {
  static const uint16_t ports[] = {3389, 445, 22, 80, 443, 139, 135, 5900, 8080, 53};
  for (uint16_t p : ports) { WiFiClient c; if (c.connect(ip, p, 300)) { c.stop(); return p; } }
  return 0;
}
const char* portName(int p) {
  switch (p) { case 3389: return "RDP"; case 445: return "SMB"; case 22: return "SSH"; case 80: return "HTTP"; case 443: return "HTTPS";
    case 139: return "NetBIOS"; case 135: return "RPC"; case 5900: return "VNC"; case 8080: return "HTTP-alt"; case 53: return "DNS"; }
  return "";
}

// ICMP first, then TCP ports, then ARP. Tells you *why* it looks down.
String pingIp(IPAddress ip, const String& label) {
  String who = esc(label) + " (" + ip.toString() + ")";
  PingStats st;
  if (icmpPing(ip, st))
    return "✅ " + who + " is up\n" + st.ok + "/4 replies, avg " + (st.sum / st.ok) + " ms (min " + st.mn + ", max " + st.mx + ")";
  if (int p = tcpProbe(ip))
    return "✅ " + who + " is up\nIgnores ping, but TCP port " + p + " (" + portName(p) + ") is open";
  IPAddress me = WiFi.localIP(); uint8_t m[6];
  if (ip[0] == me[0] && ip[1] == me[1] && ip[2] == me[2] && arpProbe(ip[3], m)) {
    String v = vendorOf(m);
    return "🟡 " + who + " is on the network but ignores ping and common ports\nMAC <code>" + macStr(m) + "</code>" + (v.length() ? " (" + esc(v) + ")" : "") + "\nProbably a firewall; Wake-on-LAN is unaffected.";
  }
  return "❌ " + who + " not found (off, asleep, or on another network)";
}

String pingDev(Dev& d, long long chat) {
  IPAddress ip;
  if (d.ip.length() && ip.fromString(d.ip)) {}
  else if (d.lastIp.length() && ip.fromString(d.lastIp)) {}
  else {
    sendMsg(chat, "No IP known for " + esc(d.name) + ", looking it up via ARP (~25 s)...");
    if (!ipForMac(d.mac, ip)) return "❌ " + esc(d.name) + " not found on the network (off, asleep, or on another subnet)";
    d.lastIp = ip.toString();
  }
  return pingIp(ip, d.name);
}

String doPingText(const String& arg, long long chat) {
  if (!arg.length()) return "Usage: /ping &lt;device|ip|hostname&gt;";
  IPAddress ip;
  if (Dev* d = findDev(arg)) return pingDev(*d, chat);
  if (ip.fromString(arg) || WiFi.hostByName(arg.c_str(), ip)) return pingIp(ip, arg);
  return "❌ can't resolve " + esc(arg);
}

// ================= sweep, presence, alerts =================
void alertNew(const Host& h) {
  String mac = macStr(h.mac), v = vendorOf(h.mac);
  Kb kb; kb.row(); kb.btn("➕ Save", "sv:" + keyOf(mac)); kb.btn("🙈 Ignore", "ig");
  sendMsg(owner, "🆕 <b>New device on the network</b>\nIP " + h.ip.toString() + "\nMAC <code>" + mac + "</code>" + (v.length() ? "\n" + esc(v) : ""), &kb);
}

void applySweep(const std::vector<Host>& hs, bool manual) {
  if (hs.empty()) return;  // router/Wi-Fi hiccup: don't mark everything offline
  lastHosts = hs;
  bool baseline = seen.empty();
  for (auto& d : devs) {
    uint8_t m[6]; if (!parseMac(d.mac, m)) continue;
    bool found = false; IPAddress fip;
    for (auto& h : hs) if (!memcmp(h.mac, m, 6)) { found = true; fip = h.ip; break; }
    if (!found && d.online && d.lastIp.length()) {  // re-probe once before declaring it gone
      IPAddress ip; uint8_t mm[6];
      if (ip.fromString(d.lastIp) && arpProbe(ip[3], mm) && !memcmp(mm, m, 6)) { found = true; fip = ip; }
    }
    if (found) {
      d.lastIp = fip.toString(); d.missed = 0;
      if (!d.online) {
        d.online = true;
        if (d.watch && presenceReady && owner) sendMsg(owner, "🟢 <b>" + esc(d.name) + "</b> is online (" + d.lastIp + ")");
      }
    } else if (d.online && ++d.missed >= 2) {
      d.online = false;
      if (d.watch && presenceReady && owner) {
        Kb kb; kb.row(); kb.btn("⚡ Wake " + d.name, "wk:" + keyOf(d.mac));
        sendMsg(owner, "🔴 <b>" + esc(d.name) + "</b> went offline", &kb);
      }
    }
  }
  presenceReady = true;
  bool changed = false;
  for (auto& h : hs) {
    String mac = macStr(h.mac);
    if (inSeen(mac)) continue;
    seen.push_back(mac); changed = true;
    if (!baseline && alertsOn && !manual && owner && !devByMac(mac).length()) alertNew(h);
  }
  if (changed) saveSeen();
}

void backgroundSweep() {
  if (!owner || !tgInited || WiFi.status() != WL_CONNECTED) return;
  std::vector<Host> hs; sweep(hs); applySweep(hs, false);
}

// ================= Wi-Fi management =================
bool tryConnect(const Net& n, uint32_t ms = 12000) {
  Serial.println("Connecting to " + n.ssid);
  WiFi.disconnect(); delay(100);
  WiFi.begin(n.ssid.c_str(), n.pass.c_str());
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < ms) waitMs(250);
  tls.stop();  // old TCP connection is dead after a network change
  if (WiFi.status() == WL_CONNECTED) { curSsid = n.ssid; Serial.println("Connected, IP " + WiFi.localIP().toString()); return true; }
  return false;
}

std::vector<Cand> visibleKnown() {
  std::vector<Cand> c;
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++)
    for (size_t j = 0; j < nets.size(); j++)
      if (WiFi.SSID(i) == nets[j].ssid) {
        bool dup = false;
        for (auto& x : c) if (x.idx == (int)j) { dup = true; if (WiFi.RSSI(i) > x.rssi) x.rssi = WiFi.RSSI(i); }
        if (!dup) c.push_back({(int)j, (int)WiFi.RSSI(i)});
      }
  WiFi.scanDelete();
  std::sort(c.begin(), c.end(), [](const Cand& a, const Cand& b) { return a.rssi > b.rssi; });
  return c;
}

bool connectBest() { for (auto& c : visibleKnown()) if (tryConnect(nets[c.idx])) return true; return false; }

// Switch if a known network is clearly stronger than the current one.
void maybeSwitch() {
  int cur = WiFi.RSSI();
  if (cur > -65) return;
  auto c = visibleKnown();
  if (c.empty() || nets[c[0].idx].ssid == curSsid || c[0].rssi < cur + 12) return;
  String old = curSsid;
  Serial.println("Switching to better network " + nets[c[0].idx].ssid);
  if (!tryConnect(nets[c[0].idx]) && old.length()) if (Net* n = findNet(old)) tryConnect(*n);
}

bool syncTime(uint32_t ms) {  // TLS certificate validation needs a correct clock
  configTime(0, 0, "pool.ntp.org", "time.google.com", "time.cloudflare.com");
  uint32_t t0 = millis();
  while (time(nullptr) < 1700000000 && millis() - t0 < ms) waitMs(200);
  timeOk = time(nullptr) >= 1700000000;
  return timeOk;
}

// ================= views (shared by commands and buttons) =================
String viewMain(Kb& kb) {
  kb.row(); kb.btn("📋 Devices", "d"); kb.btn("🔍 Scan", "scan");
  kb.row(); kb.btn("📶 Wi-Fi", "w"); kb.btn("🔔 Alerts", "al");
  kb.row(); kb.btn("📊 Status", "st"); kb.btn("⬆️ Update", "up");
  return "<b>Home network bot</b>  v" FW_VERSION "\nPick an action:";
}

String viewDevices(Kb& kb) {
  String s = "<b>Devices</b>\n";
  for (auto& d : devs) {
    s += String(d.online ? "🟢 " : "⚪ ") + "<b>" + esc(d.name) + "</b>  <code>" + d.mac + "</code>";
    String ip = bestIp(d); if (ip.length()) s += "  " + ip;
    if (d.watch) s += " 🔔";
    s += "\n";
    String k = keyOf(d.mac);
    kb.row(); kb.btn("⚡ Wake " + d.name, "wk:" + k); kb.btn("📡 Ping", "pg:" + k); kb.btn("⚙️", "dv:" + k);
  }
  if (devs.empty()) s += "(none yet, run a scan and tap a device to save it)\n";
  kb.row(); kb.btn("🔍 Scan & add", "scan"); kb.btn("⬅ Menu", "m");
  return s + "\n🟢 seen in the last scan  ⚪ not seen (not necessarily off)  🔔 alerts on";
}

String viewDevice(Kb& kb, Dev& d) {
  String k = keyOf(d.mac);
  String s = "<b>" + esc(d.name) + "</b>\nMAC <code>" + d.mac + "</code>\nIP " + (d.ip.length() ? d.ip + " (saved)" : String("not saved")) +
             (d.lastIp.length() ? "\nLast seen at " + d.lastIp : "") + "\nStatus " + (d.online ? "🟢 online" : "⚪ not seen") +
             "\nAlerts " + (d.watch ? "🔔 on" : "off (tap to enable online/offline messages)");
  kb.row(); kb.btn("⚡ Wake", "wk:" + k); kb.btn("📡 Ping", "pg:" + k);
  kb.row(); kb.btn(d.watch ? "🔕 Alerts off" : "🔔 Alerts on", "wt:" + k);
  kb.row(); kb.btn("✏️ Rename", "rn:" + k); kb.btn("🌐 Set IP", "ip:" + k);
  kb.row(); kb.btn("🗑 Delete", "dl:" + k); kb.btn("⬅ Devices", "d");
  return s;
}

String viewWifi(Kb& kb) {
  String s = "<b>Known networks</b>\n";
  for (size_t i = 0; i < nets.size(); i++) {
    bool cur = nets[i].ssid == curSsid && WiFi.status() == WL_CONNECTED;
    s += String(cur ? "● " : "○ ") + esc(nets[i].ssid) + "\n";
    kb.row(); kb.btn((cur ? "✅ " : "🔗 ") + nets[i].ssid, "wj:" + String(i)); kb.btn("🗑", "wd:" + String(i));
  }
  if (nets.empty()) s += "(none)\n";
  s += "\nNow: " + esc(curSsid) + "  " + WiFi.RSSI() + " dBm  " + WiFi.localIP().toString() + "\nAuto-switches when a known network is much stronger.";
  kb.row(); kb.btn("➕ Add network", "wa"); kb.btn("📡 Visible networks", "ws");
  kb.row(); kb.btn("⬅ Menu", "m");
  return s;
}

String viewAlerts(Kb& kb) {
  int w = 0; for (auto& d : devs) if (d.watch) w++;
  String s = "<b>Alerts</b>\nNew-device alerts: " + String(alertsOn ? "🔔 on" : "🔕 off") + "\nScan every " + sweepMin + " min\nWatched devices: " + w +
             " (toggle per device in Devices ⚙️)\nDaily update check: " + String(updCheckOn ? "on" : "off");
  kb.row(); kb.btn(alertsOn ? "🔕 Turn off new-device alerts" : "🔔 Turn on new-device alerts", alertsOn ? "af" : "ao");
  kb.row();
  for (uint32_t m : {1, 5, 15, 30}) kb.btn(String(sweepMin == m ? "● " : "") + m + " min", "ai:" + String(m));
  kb.row(); kb.btn(updCheckOn ? "Disable daily update check" : "Enable daily update check", updCheckOn ? "cf" : "co");
  kb.row(); kb.btn("⬅ Menu", "m");
  return s;
}

String viewStatus(Kb& kb) {
  kb.row(); kb.btn("🔄 Refresh", "st"); kb.btn("⬅ Menu", "m");
  return "<b>Status</b>\nFirmware v" FW_VERSION "\nWi-Fi " + esc(curSsid) + "  " + WiFi.RSSI() + " dBm\nIP " + WiFi.localIP().toString() + "\nMAC " + WiFi.macAddress() +
         "\nUptime " + (millis() / 60000) + " min\nFree heap " + ESP.getFreeHeap() + "\nDevices known: " + seen.size() + ", saved: " + devs.size();
}

String scanText(const std::vector<Host>& hs) {
  IPAddress me = WiFi.localIP();
  String out = "<b>Devices on " + String(me[0]) + "." + me[1] + "." + me[2] + ".0/24</b>\n";
  for (auto& h : hs) {
    String mac = macStr(h.mac), n = devByMac(mac), v = vendorOf(h.mac);
    out += "<code>" + h.ip.toString() + "  " + mac + "</code>";
    if (n.length()) out += "  <b>" + esc(n) + "</b>"; else if (v.length()) out += "  " + esc(v);
    out += "\n";
  }
  return out + "\n" + hs.size() + " device(s). Tap ➕ to save one.";
}

void runScan(long long chat) {
  std::vector<Host> hs; sweep(hs); applySweep(hs, true);
  Kb kb; int n = 0;
  for (auto& h : hs) {
    String mac = macStr(h.mac);
    if (devByMac(mac).length() || n >= 12) continue;
    if (n % 2 == 0) kb.row();
    String v = vendorOf(h.mac);
    kb.btn("➕ ." + String(h.ip[3]) + (v.length() && v[0] != 'p' ? " " + v : ""), "sv:" + keyOf(mac)); n++;
  }
  kb.row(); kb.btn("📋 Devices", "d"); kb.btn("⬅ Menu", "m");
  sendMsg(chat, scanText(hs), &kb);
}

// ================= firmware updates =================
void sendUpdateOffer(long long chat, const OtaInfo& i) {
  Kb kb; kb.row(); kb.btn("⬇ Install v" + i.version, "ui:" + i.version); kb.url("📄 Release notes", otaReleaseUrl(i.version));
  kb.row(); kb.btn("Later", "ig");
  sendMsg(chat, "⬆️ <b>Update available</b>\nv" + i.version + " (you have v" FW_VERSION ")\nSigned release, verified before install. Takes about a minute; keep power on.", &kb);
}

void checkForUpdate(long long chat) {
  OtaInfo i = otaCheck();
  if (!i.ok) { sendMsg(chat, "❌ Couldn't check for updates: " + esc(i.error)); return; }
  if (!i.newer) { sendMsg(chat, "✅ Up to date (v" FW_VERSION ")."); return; }
  sendUpdateOffer(chat, i);
}

bool runInstall(const String& version, String& err) {
  OtaInfo i = otaCheck();
  if (!i.ok) { err = i.error; return false; }
  if (i.version != version) { err = "the latest release is now v" + i.version + ", tap Update again"; return false; }
  if (!i.newer) { err = "already up to date"; return false; }
  Serial.println("Installing v" + i.version + ", free heap " + String(ESP.getFreeHeap()));
  if (!otaInstall(i, err, [](int pct) { Serial.printf("OTA %d%%\n", pct); })) return false;
  prefs.putString("otaFrom", FW_VERSION);
  return true;
}

// ================= text-command helpers =================
String doWifiText(std::vector<String>& t, long long chat, long long msgId) {
  String sub = t.size() > 1 ? t[1] : ""; sub.toLowerCase();
  if (sub == "add") {
    if (t.size() < 4) return "Usage: /wifi add &lt;ssid&gt; &lt;password&gt;  (or tap ➕ Add network in /wifi)";
    deleteMsg(chat, msgId);  // remove the password from chat history
    if (Net* n = findNet(t[2])) n->pass = t[3]; else nets.push_back({t[2], t[3]});
    saveNets();
    return "Saved " + esc(t[2]) + " (your message with the password was deleted)";
  }
  if (sub == "del") {
    if (t.size() < 3) return "Usage: /wifi del &lt;ssid&gt;";
    for (size_t i = 0; i < nets.size(); i++) if (nets[i].ssid == t[2]) { nets.erase(nets.begin() + i); saveNets(); return "Removed " + esc(t[2]); }
    return "Not in the list";
  }
  if (sub == "switch") {
    if (t.size() < 3) return "Usage: /wifi switch &lt;ssid&gt;";
    Net* n = findNet(t[2]); if (!n) return "Not in the list";
    String old = curSsid;
    sendMsg(chat, "Switching to " + esc(n->ssid) + "... I'll message when I'm back (if it works).");
    if (tryConnect(*n)) return "Now on " + esc(n->ssid) + ", IP " + WiFi.localIP().toString();
    if (Net* o = findNet(old)) tryConnect(*o);
    return "❌ couldn't join " + esc(t[2]) + (old.length() ? ", back on " + esc(old) : "");
  }
  return "";
}

String doAdd(std::vector<String>& t) {
  if (t.size() < 3) return "Usage: /add &lt;name&gt; &lt;mac|ip&gt; [ip]\nEasier: run /scan and tap ➕ next to a device.";
  if (!cleanText(t[1], 24)) return "Name must be 1-24 characters, no | or commas.";
  String mac, ip; uint8_t m[6];
  if (parseMac(t[2], m)) { mac = macStr(m); if (t.size() > 3 && isIp(t[3])) ip = t[3]; }
  else if (isIp(t[2])) {
    IPAddress a; a.fromString(t[2]); uint8_t found[6];
    if (!arpProbe(a[3], found) && !arpProbe(a[3], found)) return "❌ " + t[2] + " didn't answer ARP (is it on and on this subnet?). Give the MAC instead.";
    mac = macStr(found); ip = t[2];
  } else return "Second argument must be a MAC (AA:BB:CC:DD:EE:FF) or an IP.";
  if (Dev* d = findDev(t[1])) { d->mac = mac; d->ip = ip; }
  else { Dev nd; nd.name = t[1]; nd.mac = mac; nd.ip = ip; devs.push_back(nd); }
  saveDevs();
  return "Saved <b>" + esc(t[1]) + "</b>  <code>" + mac + "</code>" + (ip.length() ? "  " + ip : "");
}

String doEdit(std::vector<String>& t) {
  if (t.size() < 4) return "Usage: /edit &lt;name&gt; &lt;name|mac|ip&gt; &lt;value&gt;";
  Dev* d = findDev(t[1]); if (!d) return "No device called " + esc(t[1]);
  String f = t[2]; f.toLowerCase(); uint8_t m[6];
  if (f == "name") { if (!cleanText(t[3], 24)) return "Bad name"; if (findDev(t[3])) return "Name already used"; d->name = t[3]; }
  else if (f == "mac") { if (!parseMac(t[3], m)) return "Bad MAC"; d->mac = macStr(m); }
  else if (f == "ip") { if (t[3] == "-") d->ip = ""; else if (isIp(t[3])) d->ip = t[3]; else return "Bad IP"; }
  else return "Field must be name, mac or ip";
  saveDevs();
  return "Updated <b>" + esc(d->name) + "</b>  <code>" + d->mac + "</code>" + (d->ip.length() ? "  " + d->ip : "");
}

String doDel(std::vector<String>& t) {
  if (t.size() < 2) return "Usage: /del &lt;name&gt;";
  for (size_t i = 0; i < devs.size(); i++) if (devs[i].name.equalsIgnoreCase(t[1])) { devs.erase(devs.begin() + i); saveDevs(); return "Removed " + esc(t[1]); }
  return "No device called " + esc(t[1]);
}

// ================= pending text input (after tapping Rename / Set IP / Save / Add network) =================
void askInput(long long chat, PKind k, const String& a, const String& b, const String& prompt) {
  pending.kind = k; pending.a = a; pending.b = b; pending.t = millis();
  Kb kb; kb.row(); kb.btn("✖ Cancel", "x");
  sendMsg(chat, prompt, &kb);
}

void handlePending(long long chat, long long msgId, const String& text) {
  PKind k = pending.kind; String a = pending.a, b = pending.b; pending.kind = P_NONE;
  Kb kb; String t = text; t.trim();
  switch (k) {
    case P_NAME_NEW: {
      if (!cleanText(t, 24)) { sendMsg(chat, "Name must be 1-24 characters, no | or commas. Tap ➕ again to retry."); return; }
      if (findDev(t)) { sendMsg(chat, "That name is already used. Tap ➕ again to retry."); return; }
      Dev d; d.name = t; d.mac = macFromKey(a); d.ip = ""; d.lastIp = b; d.online = b.length() > 0; devs.push_back(d); saveDevs();
      Dev& nd = devs.back(); String s = viewDevice(kb, nd); sendMsg(chat, "✅ Saved!\n\n" + s, &kb); break;
    }
    case P_RENAME: {
      Dev* d = devByKey(a);
      if (!d) { sendMsg(chat, "Device not found."); return; }
      if (!cleanText(t, 24) || (findDev(t) && findDev(t) != d)) { sendMsg(chat, "Invalid or already used name. Tap ✏️ Rename again."); return; }
      d->name = t; saveDevs(); String s = viewDevice(kb, *d); sendMsg(chat, s, &kb); break;
    }
    case P_SETIP: {
      Dev* d = devByKey(a);
      if (!d) { sendMsg(chat, "Device not found."); return; }
      if (t == "-") d->ip = ""; else if (isIp(t)) d->ip = t; else { sendMsg(chat, "That's not an IP. Tap 🌐 Set IP again (send - to clear)."); return; }
      saveDevs(); String s = viewDevice(kb, *d); sendMsg(chat, s, &kb); break;
    }
    case P_WIFI_SSID: {
      if (!cleanText(t, 32)) { sendMsg(chat, "SSID must be 1-32 characters, no | or commas. Tap ➕ Add network again."); return; }
      askInput(chat, P_WIFI_PASS, t, "", "Password for <b>" + esc(t) + "</b>? (send - for an open network; your message will be deleted)"); break;
    }
    case P_WIFI_PASS: {
      deleteMsg(chat, msgId);  // keep the password out of chat history
      String pw = t == "-" ? "" : t;
      if (pw.indexOf('\t') >= 0 || pw.indexOf('\n') >= 0 || (pw.length() && (pw.length() < 8 || pw.length() > 63))) { sendMsg(chat, "Wi-Fi passwords are 8-63 characters. Tap ➕ Add network to retry."); return; }
      if (Net* n = findNet(a)) n->pass = pw; else nets.push_back({a, pw});
      saveNets();
      kb.row(); kb.btn("🔗 Join now", "wj:" + String(findNet(a) - &nets[0])); kb.btn("📶 Wi-Fi", "w");
      sendMsg(chat, "✅ Saved <b>" + esc(a) + "</b> (password message deleted)", &kb); break;
    }
    default: break;
  }
}

// ================= button handling =================
void handleCb(long long chat, long long msgId, const String& id, const String& data) {
  if (chat != owner) { answerCb(id); return; }
  String cmd = data, arg; int c = data.indexOf(':');
  if (c > 0) { cmd = data.substring(0, c); arg = data.substring(c + 1); }
  Kb kb;

  if (cmd == "m") { answerCb(id); String s = viewMain(kb); show(chat, msgId, s, &kb); }
  else if (cmd == "d") { answerCb(id); String s = viewDevices(kb); show(chat, msgId, s, &kb); }
  else if (cmd == "st") { answerCb(id); String s = viewStatus(kb); show(chat, msgId, s, &kb); }
  else if (cmd == "w") { answerCb(id); String s = viewWifi(kb); show(chat, msgId, s, &kb); }
  else if (cmd == "al") { answerCb(id); String s = viewAlerts(kb); show(chat, msgId, s, &kb); }
  else if (cmd == "ao" || cmd == "af") { alertsOn = cmd == "ao"; saveSettings(); answerCb(id, alertsOn ? "New-device alerts on" : "New-device alerts off"); String s = viewAlerts(kb); show(chat, msgId, s, &kb); }
  else if (cmd == "co" || cmd == "cf") { updCheckOn = cmd == "co"; saveSettings(); answerCb(id, updCheckOn ? "Daily update check on" : "Daily update check off"); String s = viewAlerts(kb); show(chat, msgId, s, &kb); }
  else if (cmd == "ai") { sweepMin = constrain(arg.toInt(), 1, 60); saveSettings(); nextSweep = millis() + sweepMin * 60000UL; answerCb(id, "Scanning every " + String(sweepMin) + " min"); String s = viewAlerts(kb); show(chat, msgId, s, &kb); }
  else if (cmd == "scan") { answerCb(id, "Scanning, ~25 s..."); runScan(chat); }
  else if (cmd == "up") { answerCb(id, "Checking GitHub..."); checkForUpdate(chat); }
  else if (cmd == "ui") {
    answerCb(id, "Downloading...");
    sendMsg(chat, "⬇ Downloading v" + esc(arg) + ", verifying signature... don't unplug me.");
    String err;
    if (runInstall(arg, err)) {
      sendMsg(chat, "✅ Installed. Rebooting now; I'll say hi when I'm back.");
      delay(1000); ESP.restart();
    } else sendMsg(chat, "❌ Update failed: " + esc(err) + "\nNothing was changed.");
  }
  else if (cmd == "ig") { answerCb(id, "Ok"); deleteMsg(chat, msgId); }
  else if (cmd == "x") { pending.kind = P_NONE; answerCb(id, "Cancelled"); deleteMsg(chat, msgId); }
  else if (cmd == "dv") { Dev* d = devByKey(arg); answerCb(id); if (d) { String s = viewDevice(kb, *d); show(chat, msgId, s, &kb); } }
  else if (cmd == "wk") {
    Dev* d = devByKey(arg); if (!d) { answerCb(id, "Device not found"); return; }
    answerCb(id, "⚡ Sending to " + d->name);
    Kb k2; k2.row(); k2.btn("📡 Ping " + d->name, "pg:" + arg); k2.btn("📋 Devices", "d");
    sendMsg(chat, wake(d->mac), &k2);
  }
  else if (cmd == "pg") {
    Dev* d = devByKey(arg); if (!d) { answerCb(id, "Device not found"); return; }
    answerCb(id, "📡 Pinging " + d->name + "...");
    String r = pingDev(*d, chat);
    Kb k2; k2.row(); k2.btn("🔄 Again", "pg:" + arg); k2.btn("⚡ Wake", "wk:" + arg); k2.btn("📋 Devices", "d");
    sendMsg(chat, r, &k2);
  }
  else if (cmd == "wt") {
    Dev* d = devByKey(arg); if (!d) { answerCb(id); return; }
    d->watch = !d->watch; saveDevs(); answerCb(id, d->watch ? "🔔 Alerts on" : "🔕 Alerts off");
    String s = viewDevice(kb, *d); show(chat, msgId, s, &kb);
  }
  else if (cmd == "rn") { Dev* d = devByKey(arg); answerCb(id); if (d) askInput(chat, P_RENAME, arg, "", "New name for <b>" + esc(d->name) + "</b>?"); }
  else if (cmd == "ip") { Dev* d = devByKey(arg); answerCb(id); if (d) askInput(chat, P_SETIP, arg, "", "IP address for <b>" + esc(d->name) + "</b>? (send - to clear)"); }
  else if (cmd == "dl") {
    Dev* d = devByKey(arg); answerCb(id); if (!d) return;
    kb.row(); kb.btn("🗑 Yes, delete", "dy:" + arg); kb.btn("Cancel", "dv:" + arg);
    show(chat, msgId, "Delete <b>" + esc(d->name) + "</b>?", &kb);
  }
  else if (cmd == "dy") {
    for (size_t i = 0; i < devs.size(); i++) if (keyOf(devs[i].mac) == arg) { devs.erase(devs.begin() + i); saveDevs(); break; }
    answerCb(id, "Deleted"); String s = viewDevices(kb); show(chat, msgId, s, &kb);
  }
  else if (cmd == "sv") {
    String mac = macFromKey(arg); answerCb(id);
    if (devByMac(mac).length()) { sendMsg(chat, "Already saved as <b>" + esc(devByMac(mac)) + "</b>."); return; }
    String ip; uint8_t m[6]; bool okMac = parseMac(mac, m);
    if (okMac) for (auto& h : lastHosts) if (!memcmp(h.mac, m, 6)) ip = h.ip.toString();
    String v = okMac ? vendorOf(m) : "";
    askInput(chat, P_NAME_NEW, arg, ip, "Name for <code>" + mac + "</code>" + (ip.length() ? " (" + ip + ")" : "") + (v.length() ? " " + esc(v) : "") + "?");
  }
  else if (cmd == "wj") {
    size_t i = arg.toInt(); if (i >= nets.size()) { answerCb(id, "Not found"); return; }
    if (nets[i].ssid == curSsid && WiFi.status() == WL_CONNECTED) { answerCb(id, "Already connected"); return; }
    answerCb(id, "Switching...");
    String old = curSsid, target = nets[i].ssid;
    sendMsg(chat, "Switching to <b>" + esc(target) + "</b>... I'll message when I'm back (if it works).");
    Net n = nets[i];
    if (tryConnect(n)) sendMsg(chat, "✅ Now on <b>" + esc(target) + "</b>, IP " + WiFi.localIP().toString());
    else { if (Net* o = findNet(old)) tryConnect(*o); sendMsg(chat, "❌ Couldn't join " + esc(target) + (old.length() ? ", back on " + esc(old) : "")); }
  }
  else if (cmd == "wd") {
    size_t i = arg.toInt(); answerCb(id); if (i >= nets.size()) return;
    kb.row(); kb.btn("🗑 Yes, remove", "wy:" + arg); kb.btn("Cancel", "w");
    show(chat, msgId, "Remove network <b>" + esc(nets[i].ssid) + "</b>?" + (nets[i].ssid == curSsid ? "\n⚠️ You're connected to it right now; I stay connected until it drops." : ""), &kb);
  }
  else if (cmd == "wy") {
    size_t i = arg.toInt(); if (i < nets.size()) { nets.erase(nets.begin() + i); saveNets(); }
    answerCb(id, "Removed"); String s = viewWifi(kb); show(chat, msgId, s, &kb);
  }
  else if (cmd == "wa") { answerCb(id); askInput(chat, P_WIFI_SSID, "", "", "Network name (SSID) to add? Only 2.4 GHz networks work."); }
  else if (cmd == "ws") {
    answerCb(id, "Scanning Wi-Fi...");
    int n = WiFi.scanNetworks(); scannedSsids.clear();
    std::vector<int> order; for (int i = 0; i < n; i++) order.push_back(i);
    std::sort(order.begin(), order.end(), [](int a, int b) { return WiFi.RSSI(a) > WiFi.RSSI(b); });
    String s = "<b>Visible networks</b> (2.4 GHz only)\n";
    for (int i : order) {
      String ssid = WiFi.SSID(i); if (!ssid.length() || scannedSsids.size() >= 12) continue;
      bool dup = false; for (auto& x : scannedSsids) if (x == ssid) dup = true; if (dup) continue;
      bool known = findNet(ssid) != nullptr;
      s += String(known ? "✔ " : "• ") + esc(ssid) + "  " + WiFi.RSSI(i) + " dBm\n";
      if (scannedSsids.size() % 2 == 0) kb.row();
      kb.btn(String(known ? "✔ " : "") + ssid, "wn:" + String(scannedSsids.size()));
      scannedSsids.push_back(ssid);
    }
    WiFi.scanDelete();
    kb.row(); kb.btn("⬅ Wi-Fi", "w");
    show(chat, msgId, s + "\nTap a network to add it (✔ = already known).", &kb);
  }
  else if (cmd == "wn") {
    size_t i = arg.toInt(); answerCb(id); if (i >= scannedSsids.size()) return;
    askInput(chat, P_WIFI_PASS, scannedSsids[i], "", "Password for <b>" + esc(scannedSsids[i]) + "</b>? (send - for an open network; your message will be deleted)");
  }
  else answerCb(id);
}

// ================= text commands =================
void handle(long long chat, long long msgId, String text) {
  text.trim();
  auto t = tokens(text); if (t.empty()) return;
  String cmd = t[0]; int at = cmd.indexOf('@'); if (at > 0) cmd = cmd.substring(0, at); cmd.toLowerCase();
  int sp = text.indexOf(' ');
  String rest = sp > 0 ? text.substring(sp + 1) : ""; rest.trim();

  if (owner == 0) {  // unclaimed: only /claim <PIN> works. The PIN is shown on the serial console only.
    if (cmd == "/claim" && t.size() > 1) {
      if (claimLockUntil && (int32_t)(millis() - claimLockUntil) < 0) return;  // locked out after too many wrong PINs
      if (t[1] == claimPin) {
        owner = chat; claimFails = 0; prefs.putLong64("owner", owner); deleteMsg(chat, msgId);
        Kb kb; String s = viewMain(kb); sendMsg(chat, "✅ You're the owner now.\n\n" + s, &kb);
      } else if (++claimFails >= 5) {
        claimFails = 0; claimLockUntil = millis() + 900000UL; deleteMsg(chat, msgId);
        sendMsg(chat, "Too many wrong PINs. Claiming is locked for 15 minutes.");
      } else deleteMsg(chat, msgId);
    } else if (cmd == "/start") sendMsg(chat, "This bot isn't claimed yet. Send <code>/claim PIN</code>; the PIN is printed on the device's serial console (<code>pin show</code>).");
    return;
  }
  if (chat != owner) return;

  if (cmd == "/cancel") { pending.kind = P_NONE; sendMsg(chat, "Cancelled."); return; }
  if (cmd[0] != '/') {  // plain text: answer to a pending question?
    if (pending.kind != P_NONE && millis() - pending.t < 300000) handlePending(chat, msgId, text);
    else { pending.kind = P_NONE; Kb kb; String s = viewMain(kb); sendMsg(chat, s, &kb); }
    return;
  }
  pending.kind = P_NONE;
  Kb kb;
  if (cmd == "/start" || cmd == "/menu") { String s = viewMain(kb); sendMsg(chat, s, &kb); }
  else if (cmd == "/help")
    sendMsg(chat, "Tap /menu for buttons. Typed commands:\n/devices /scan /status /wifi /alerts /update\n/add &lt;name&gt; &lt;mac|ip&gt;  /edit &lt;name&gt; name|mac|ip &lt;value&gt;  /del &lt;name&gt;\n/wake &lt;device|mac&gt;  /ping &lt;device|ip|host&gt;\n/wifi add &lt;ssid&gt; &lt;pw&gt;  /wifi del &lt;ssid&gt;  /wifi switch &lt;ssid&gt;");
  else if (cmd == "/devices" || cmd == "/list") { String s = viewDevices(kb); sendMsg(chat, s, &kb); }
  else if (cmd == "/add") sendMsg(chat, doAdd(t));
  else if (cmd == "/edit") sendMsg(chat, doEdit(t));
  else if (cmd == "/del") sendMsg(chat, doDel(t));
  else if (cmd == "/wake") sendMsg(chat, wake(rest));
  else if (cmd == "/ping") sendMsg(chat, doPingText(rest, chat));
  else if (cmd == "/scan") { sendMsg(chat, "Scanning, ~25 s..."); runScan(chat); }
  else if (cmd == "/alerts") { String s = viewAlerts(kb); sendMsg(chat, s, &kb); }
  else if (cmd == "/update") { sendMsg(chat, "Checking GitHub for updates..."); checkForUpdate(chat); }
  else if (cmd == "/status") { String s = viewStatus(kb); sendMsg(chat, s, &kb); }
  else if (cmd == "/wifi") {
    String r = t.size() > 1 ? doWifiText(t, chat, msgId) : "";
    if (r.length()) sendMsg(chat, r); else { String s = viewWifi(kb); sendMsg(chat, s, &kb); }
  }
  else sendMsg(chat, "Unknown command. /menu");
}

bool skipBacklog() {  // don't replay old commands/taps after a reboot
  String body;
  if (tgCall("getUpdates?offset=-1&timeout=0", "", &body) != 200) return false;
  JsonDocument d;
  if (!deserializeJson(d, body)) for (JsonObject u : d["result"].as<JsonArray>()) lastUpdate = u["update_id"].as<long long>();
  return true;
}

void poll() {
  String body;
  int code = tgCall("getUpdates?timeout=5&offset=" + String((long)(lastUpdate + 1)), "", &body, 20000);
  if (code != 200) { waitMs(2000); return; }
  JsonDocument d;
  if (deserializeJson(d, body)) return;
  for (JsonObject u : d["result"].as<JsonArray>()) {
    lastUpdate = u["update_id"].as<long long>();  // advance first: a crashing handler can't replay forever
    if (u["message"]["text"].is<const char*>())
      handle(u["message"]["chat"]["id"].as<long long>(), u["message"]["message_id"].as<long long>(), u["message"]["text"].as<String>());
    else if (!u["callback_query"].isNull()) {
      JsonObject cq = u["callback_query"];
      handleCb(cq["message"]["chat"]["id"].as<long long>(), cq["message"]["message_id"].as<long long>(), cq["id"].as<String>(), cq["data"].as<String>());
    }
  }
}

// ================= USB serial console (provisioning + diagnostics) =================
void conOk(const String& s) { Serial.println("OK " + s); }
void conErr(const String& s) { Serial.println("ERR " + s); }

void consoleRun(String line) {
  auto t = tokens(line); if (t.empty()) return;
  String c = t[0]; c.toLowerCase();
  String sub = t.size() > 1 ? t[1] : ""; sub.toLowerCase();

  if (c == "help") {
    Serial.println("Commands:\n  status\n  token <bot token> | token clear\n  wifi list | wifi add <ssid> <password> | wifi del <ssid>\n"
                   "  pin show | pin new          claim PIN for /claim in Telegram\n  owner reset                 let a new chat claim the bot\n"
                   "  update check | update install\n  scan                        ARP scan of the LAN\n  factory-reset yes | reboot");
  } else if (c == "status") {
    Serial.printf("version %s\nwifi %s %s rssi %d\ntime %s\ntoken %s\nowner %s\ntelegram %s\nheap %u\n", FW_VERSION, WiFi.status() == WL_CONNECTED ? curSsid.c_str() : "(not connected)",
                  WiFi.localIP().toString().c_str(), WiFi.RSSI(), timeOk ? "synced" : "NOT synced", botToken.length() ? "set" : "MISSING", owner ? "claimed" : "unclaimed",
                  tgOk ? "ok" : "not ok", ESP.getFreeHeap());
  } else if (c == "token") {
    if (sub == "clear") { botToken = ""; prefs.remove("token"); tgInited = false; tls.stop(); conOk("token cleared"); }
    else if (t.size() == 2 && t[1].indexOf(':') > 0 && t[1].length() >= 35) {
      botToken = t[1]; prefs.putString("token", botToken); tgInited = false; tgOk = false; lastUpdate = 0; tls.stop(); conOk("token stored (" + String(botToken.length()) + " chars)");
    } else conErr("usage: token <123456:ABC...> (from @BotFather)");
  } else if (c == "wifi") {
    if (sub == "list") { for (auto& n : nets) Serial.println("  " + n.ssid); conOk(String(nets.size()) + " network(s)"); }
    else if (sub == "add") {
      String rest = line.substring(line.indexOf("add") + 3); rest.trim();
      String ssid, pass;
      if (rest.startsWith("\"")) { int e = rest.indexOf('"', 1); if (e < 0) { conErr("unterminated quote"); return; } ssid = rest.substring(1, e); pass = rest.substring(e + 1); }
      else { int e = rest.indexOf(' '); ssid = e < 0 ? rest : rest.substring(0, e); pass = e < 0 ? "" : rest.substring(e + 1); }
      if (pass.startsWith(" ")) pass.remove(0, 1);
      if (!cleanText(ssid, 32)) { conErr("SSID must be 1-32 chars, no | or comma"); return; }
      if (pass.length() && (pass.length() < 8 || pass.length() > 63)) { conErr("password must be 8-63 chars (omit it for an open network)"); return; }
      if (Net* n = findNet(ssid)) n->pass = pass; else nets.push_back({ssid, pass});
      saveNets(); conOk("saved " + ssid);
    } else if (sub == "del" && t.size() > 2) {
      for (size_t i = 0; i < nets.size(); i++) if (nets[i].ssid == t[2]) { nets.erase(nets.begin() + i); saveNets(); conOk("removed"); return; }
      conErr("not found");
    } else conErr("usage: wifi list | wifi add <ssid> <password> | wifi del <ssid>");
  } else if (c == "pin") {
    if (sub == "new") { claimPin = newPin(); prefs.putString("pin", claimPin); }
    Serial.println("claim PIN: " + claimPin + (owner ? "  (bot is already claimed; use 'owner reset' to allow a new claim)" : "  (send /claim " + claimPin + " to your bot)"));
  } else if (c == "owner" && sub == "reset") {
    owner = 0; prefs.remove("owner"); conOk("owner cleared, bot is claimable again with the PIN");
  } else if (c == "update") {
    if (WiFi.status() != WL_CONNECTED || !timeOk) { conErr("needs Wi-Fi and a synced clock"); return; }
    OtaInfo i = otaCheck();
    if (!i.ok) { conErr(i.error); return; }
    Serial.println("latest signed release: v" + i.version + ", running v" FW_VERSION);
    if (sub == "install") {
      if (!i.newer) { conOk("already up to date"); return; }
      String err;
      if (runInstall(i.version, err)) { conOk("installed, rebooting"); delay(500); ESP.restart(); } else conErr(err);
    } else conOk(i.newer ? "update available (run: update install)" : "up to date");
  } else if (c == "scan") {
    if (WiFi.status() != WL_CONNECTED) { conErr("not connected"); return; }
    std::vector<Host> hs; sweep(hs);
    for (auto& h : hs) { String v = vendorOf(h.mac); Serial.println("  " + h.ip.toString() + "  " + macStr(h.mac) + "  " + devByMac(macStr(h.mac)) + (v.length() ? " " + v : "")); }
    conOk(String(hs.size()) + " device(s)");
  } else if (c == "factory-reset" && sub == "yes") {
    prefs.clear(); conOk("wiped, rebooting"); delay(300); ESP.restart();
  } else if (c == "reboot") { conOk("rebooting"); delay(300); ESP.restart(); }
  else conErr("unknown command, type help");
}

void consoleTick() {
  while (Serial.available()) {
    char ch = Serial.read();
    if (ch == '\r') continue;
    if (ch == '\n') { String l = conLine; conLine = ""; l.trim(); if (l.length()) consoleRun(l); }
    else if (conLine.length() < 300) conLine += ch;
  }
}

// ================= setup / loop =================
bool tgInit() {  // first contact after boot or token change
  if (!skipBacklog()) return false;
  setCommands();
  tgInited = true;
  if (owner) {
    String from = prefs.getString("otaFrom", "");
    Kb kb; kb.row(); kb.btn("📋 Menu", "m");
    if (from.length()) { prefs.remove("otaFrom"); sendMsg(owner, "✅ Updated from v" + esc(from) + " to <b>v" FW_VERSION "</b> on <b>" + esc(curSsid) + "</b> (" + WiFi.localIP().toString() + ")", &kb); }
    else sendMsg(owner, "ESP32 online on <b>" + esc(curSsid) + "</b> at " + WiFi.localIP().toString() + "  (v" FW_VERSION ")", &kb);
  }
  return true;
}

void healthCheck() {  // confirm a freshly OTA-flashed image is healthy, or force a rollback
  if (rollbackCleared) return;
  bool healthy = WiFi.status() == WL_CONNECTED && (botToken.length() ? tgOk : millis() > 60000);
  if (healthy && millis() > 15000) {
    esp_ota_mark_app_valid_cancel_rollback();
    rollbackCleared = true;
    return;
  }
  esp_ota_img_states_t st;
  if (millis() > 300000 && esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY) {
    Serial.println("New firmware never became healthy, rolling back");
    esp_ota_mark_app_invalid_rollback_and_reboot();
  }
}

void setup() {
  Serial.setRxBufferSize(1024);
  Serial.begin(115200);
  Serial.println("\nesp32-netbot v" FW_VERSION " (type 'help' for the serial console)");
  loadAll();
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(false);  // we manage reconnects ourselves
  tls.useBuiltinCACertBundle();  // verify Telegram's certificate chain (needs a valid clock, see syncTime)
  if (!botToken.length()) Serial.println("SETUP NEEDED: no bot token. Run: token <token from @BotFather>");
  if (nets.empty()) Serial.println("SETUP NEEDED: no Wi-Fi saved. Run: wifi add <ssid> <password>");
  if (!owner) Serial.println("Claim PIN: " + claimPin + "  (after setup, send /claim " + claimPin + " to the bot)");
  while (!connectBest()) {
    Serial.println(nets.empty() ? "Waiting for a Wi-Fi network (use the console)..." : "No known network reachable, retrying...");
    waitMs(5000);
  }
  syncTime(15000);
  lastCheck = millis();
  nextSweep = millis() + 20000;       // first background sweep shortly after boot (silent baseline)
  nextUpdCheck = millis() + 600000;   // first daily update check 10 min after boot
}

void loop() {
  consoleTick();
  if (WiFi.status() != WL_CONNECTED) {
    if (!connectBest()) waitMs(5000);
    return;
  }
  if (!timeOk) { syncTime(3000); if (!timeOk) { waitMs(2000); return; } }
  if (!botToken.length()) { waitMs(500); healthCheck(); return; }
  if (!tgInited && !tgInit()) { waitMs(3000); return; }
  poll();
  healthCheck();
  if (millis() - lastCheck > 300000) { lastCheck = millis(); maybeSwitch(); }
  if ((int32_t)(millis() - nextSweep) >= 0) { backgroundSweep(); nextSweep = millis() + sweepMin * 60000UL; }
  if (updCheckOn && owner && rollbackCleared && (int32_t)(millis() - nextUpdCheck) >= 0) {
    nextUpdCheck = millis() + 86400000UL;
    OtaInfo i = otaCheck();
    if (i.ok && i.newer && i.version != lastOfferedVer) { lastOfferedVer = i.version; sendUpdateOffer(owner, i); }
  }
}
