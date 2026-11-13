#pragma once
// Types used in function signatures. They live in a header because the Arduino build
// generates function prototypes above any struct defined mid-sketch.
#include <ArduinoJson.h>
#include <stdint.h>

struct Kb {  // Telegram inline keyboard builder
  JsonDocument doc; JsonArray rows, cur;
  Kb() { rows = doc["inline_keyboard"].to<JsonArray>(); }
  void row() { cur = rows.add<JsonArray>(); }
  void btn(const String& text, const String& data) {
    if (cur.isNull()) row();
    JsonObject b = cur.add<JsonObject>(); b["text"] = text; b["callback_data"] = data;
  }
  void url(const String& text, const String& link) {
    if (cur.isNull()) row();
    JsonObject b = cur.add<JsonObject>(); b["text"] = text; b["url"] = link;
  }
};

struct PingStats { volatile bool done = false; uint32_t ok = 0, sum = 0, mn = 0xFFFFFFFF, mx = 0; };

struct Cand { int idx; int rssi; };
