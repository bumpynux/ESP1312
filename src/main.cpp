// ESP1312: geotagged WiFi + BLE surveillance logger for the M5Stack Cardputer ADV.
//
// Logs WiFi beacons, WiFi probe requests, and BLE adverts with the fields most wardrivers
// drop (company ID, manufacturer data, service UUIDs, address type) so gear that rotates
// its MAC still gets caught. Probe requests matter because some gear never beacons, it only
// calls out for its network, and a probe from a real MAC still pins it.
//
// Keys:  TAB home/details/threats   M mode (ALL / HUNT / WIGLE)   S scan passive/active
//        P pause/resume   N new file   ; . page through threats
#include <M5Cardputer.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SPI.h>
#include <SD.h>
#include <TinyGPSPlus.h>
#include <NimBLEDevice.h>
#include <time.h>
#include <algorithm>
#include "driver/gpio.h"
#include "esp_private/periph_ctrl.h"
#include "signatures.h"

#ifndef SD_SCK
#define SD_SCK 40
#define SD_MISO 39
#define SD_MOSI 14
#define SD_CS 12
#endif
#ifndef GPS_RX
#define GPS_RX 15
#define GPS_TX 13
#endif
#ifndef GPS_BAUD
#define GPS_BAUD 115200
#endif
#ifndef TZ_HOURS
#define TZ_HOURS 0        // offset for the date in file names only; CSV times stay UTC
#endif

// Semantic version, MAJOR.MINOR.PATCH. 0.x means pre-release, not yet a firmware
// a stranger could flash fresh and drive with. Bumped by hand, never automatically.
#define FW_VERSION "0.1.5"

static const char*    LOG_DIR    = "/ESP1312";
static const double   RELOG_M    = 25.0;           // re-log a known MAC after it moves this far...
static const uint32_t RELOG_MS   = 20000;          // ...or this much time passes
static const int      SEEN_MAX   = 1000;           // 32 B each, RAM is tight with both radios up
static const uint32_t WIFI_DWELL = 220;            // ms per channel, enough for a passive beacon catch
static const uint32_t SCREEN_OFF_MS = 60000;       // backlight off after this long with no keys
#define RING 48

enum Mode { ALL, HUNT, WIGLE };
static const char* MODE_NAME[] = { "ALL", "HUNT", "WIGLE" };
static const char* MODE_HINT[] = { "every device", "threats only", "wigle upload" };
static const char* MODE_FILE[] = { "log", "hits", "wigle" };

enum Kind : uint8_t { K_WIFI, K_BLE, K_PROBE, K_RID };   // AP beacon, BLE advert, WiFi probe request, drone Remote ID
static const char* TYPE_NAME[] = { "WIFI", "BLE", "PROBE", "RID" };

struct Rec  { char mac[18], name[24], company[5], mdata[9], uuids[40], enc[6]; int8_t rssi; uint8_t chan; Kind kind; };
struct Seen { char mac[18]; Kind kind; float lat, lon; uint32_t last; };   // float is ~1 m, fine for a 25 m rule

static Mode     mode = ALL;
static bool     active = false, logging = true, sdOk = false;
static int      view = 0;                  // 0 home, 1 details, 2 threats

// every signature hit seen, newest first on the threats screen
#define HITS_MAX 12
struct Hit { char mac[18], vendor[12], method[24]; int8_t rssi; Kind kind; uint32_t last; };
static Hit      hits[HITS_MAX];
static int      hitsN = 0, hitScroll = 0;
static bool     asleep = false;
static uint32_t lastKey = 0;
static uint8_t  brightness = 0;            // what to restore on wake
static File     file;
static char     filePath[48] = "";
static bool     fileDated = false;         // renamed with the GPS date yet?
static uint32_t rows = 0, wifiN = 0, bleN = 0, probeN = 0, threats = 0;
static char     lastHit[32] = "";
static HardwareSerial gpsSerial(1);
static TinyGPSPlus    gps;
static M5Canvas       canvas(&M5Cardputer.Display);
static Seen     seen[SEEN_MAX];
static int      seenN = 0, seenNext = 0;

// BLE results arrive on the NimBLE task and sniffed frames on the WiFi task, so both go
// into a ring and loop() drains it.
static Rec              ring[RING];
static volatile uint8_t rHead = 0, rTail = 0;
static portMUX_TYPE     rMux = portMUX_INITIALIZER_UNLOCKED;

static void push(const Rec& e) {
  portENTER_CRITICAL(&rMux);
  uint8_t next = (rHead + 1) % RING;
  if (next != rTail) { ring[rHead] = e; rHead = next; }   // full: drop it, the air repeats itself
  portEXIT_CRITICAL(&rMux);
}

// ---- helpers ----------------------------------------------------------------
static void lowerStr(char* s) { for (; *s; s++) *s = (char)tolower((unsigned char)*s); }

static const char* encName(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN:            return "OPEN";
    case WIFI_AUTH_WEP:             return "WEP";
    case WIFI_AUTH_WPA_PSK:         return "WPA";
    case WIFI_AUTH_WPA2_PSK:
    case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2E";
    case WIFI_AUTH_WPA3_PSK:
    case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA3";
    default:                        return "?";
  }
}

// ---- BLE --------------------------------------------------------------------
struct ScanCB : NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* d) override {
    Rec e = {}; e.kind = K_BLE;
    const NimBLEAddress& a = d->getAddress();
    strlcpy(e.mac, a.toString().c_str(), sizeof e.mac); lowerStr(e.mac);
    strlcpy(e.enc, a.isPublic() ? "pub" : a.isRpa() ? "rpa" : a.isNrpa() ? "nrpa" : "rnd", sizeof e.enc);
    e.rssi = d->getRSSI();
    if (d->haveName()) { strlcpy(e.name, d->getName().c_str(), sizeof e.name); csvSafe(e.name, sizeof e.name); }
    if (d->haveManufacturerData()) {
      std::string m = d->getManufacturerData();
      if (m.size() >= 2) snprintf(e.company, sizeof e.company, "%02x%02x", (uint8_t)m[1], (uint8_t)m[0]);
      // first bytes after the company ID: Apple type 0x12 is Find My, which is how AirTags show up
      for (size_t i = 2; i < m.size() && i < 6; i++) snprintf(e.mdata + 2 * (i - 2), 3, "%02x", (uint8_t)m[i]);
    }
    // service UUIDs from both the UUID list and service data. Remote ID (0xfffa) only uses the latter.
    std::string u;
    for (uint8_t i = 0; i < d->getServiceUUIDCount() && u.size() < 36; i++) u += d->getServiceUUID(i).toString() + " ";
    for (uint8_t i = 0; i < d->getServiceDataCount() && u.size() < 36; i++) u += d->getServiceDataUUID(i).toString() + " ";
    if (!u.empty()) u.pop_back();   // no trailing space in the CSV
    strlcpy(e.uuids, u.c_str(), sizeof e.uuids); lowerStr(e.uuids); csvSafe(e.uuids, sizeof e.uuids);
    push(e);
  }
} scanCB;

static void startBle() {
  NimBLEScan* s = NimBLEDevice::getScan();
  s->stop();
  s->setScanCallbacks(&scanCB);
  s->setActiveScan(active);
  s->setInterval(80);
  s->setWindow(80);      // full duty; a reduced-duty guard against a suspected battery brownout was tested on battery and wasn't needed
  s->setDuplicateFilter(false);
  s->setMaxResults(0);
  s->start(0, false, false);   // forever
}

// ---- GPS --------------------------------------------------------------------
// Start at GPS_BAUD and rotate every 5 s until NMEA checksums pass. This cap runs at
// 115200; 9600 is the ATGM336H default, in case a fresh or reset module comes up there.
static const int BAUDS[] = { GPS_BAUD, 9600 };
static int baudIdx = 0;

// The Cap LoRa-1262 GPS is a CASIC AT6558/ATGM336H. It can boot with its NMEA
// output turned off (a prior firmware like Meshtastic sends "$PCAS03,0..." and the
// module keeps it), which leaves a passive reader seeing nothing. So on every baud
// we open, we re-send "$PCAS03,1..." to turn GGA+RMC back on. This is non-destructive
// (no reset, no cold start, the fix and almanac survive) and harmless if already on;
// verified on-device to un-mute a silenced module while keeping a live fix.
static void gpsEnable() { gpsSerial.print("$PCAS03,1,0,0,0,1,0,0,0,0,0,,,0,0*02\r\n"); }

static void gpsBegin() {
  gpsSerial.begin(BAUDS[baudIdx], SERIAL_8N1, GPS_RX, GPS_TX);
  delay(30);        // let the UART settle before the module has to receive the command
  gpsEnable();
}

static void gpsAutoBaud() {
  static uint32_t t = 0, good = 0;
  static int miss = 0;
  if (millis() - t < 5000) return;
  t = millis();
  if (gps.passedChecksum() > good) { good = gps.passedChecksum(); miss = 0; return; }
  // No valid NMEA. First re-send the enable at the CURRENT baud, since a module muted at the
  // right rate un-mutes without us leaving it. Only rotate if re-enabling keeps failing.
  gpsEnable();
  if (++miss >= 2) { miss = 0; baudIdx = (baudIdx + 1) % 2; gpsSerial.end(); gpsBegin(); }
}

static void gpsTime(char* b, size_t n) {
  b[0] = 0;
  if (gps.date.isValid() && gps.time.isValid() && gps.date.year() >= 2020)
    snprintf(b, n, "%04d-%02d-%02d %02d:%02d:%02d", gps.date.year(), gps.date.month(), gps.date.day(),
             gps.time.hour(), gps.time.minute(), gps.time.second());
}

// ---- SD / files -------------------------------------------------------------
// Files open as /ESP1312/log_N.csv and move into a /ESP1312/YYYY-MM-DD/ day folder
// once GPS knows the date. One small folder per day keeps openFile()'s directory scan
// fast no matter how many days pile up.
static bool gpsDate(char* b, size_t n) {
  if (!gps.date.isValid() || !gps.time.isValid() || gps.date.year() < 2020) { b[0] = 0; return false; }
  struct tm t = {};
  t.tm_year = gps.date.year() - 1900; t.tm_mon = gps.date.month() - 1; t.tm_mday = gps.date.day();
  t.tm_hour = gps.time.hour(); t.tm_min = gps.time.minute();
  time_t u = mktime(&t) + TZ_HOURS * 3600;   // no TZ set on the device, so mktime is UTC
  struct tm* l = gmtime(&u);
  snprintf(b, n, "%04d-%02d-%02d", l->tm_year + 1900, l->tm_mon + 1, l->tm_mday);
  return true;
}

// first unused dir/<mode>_N.csv, counting up from `from`
static void freePath(char* out, size_t n, const char* dir, int from) {
  for (int i = from; i < from + 10000; i++) {
    snprintf(out, n, "%s/%s_%d.csv", dir, MODE_FILE[mode], i);
    if (!SD.exists(out)) break;
  }
}

static void openFile() {
  if (!sdOk) return;
  if (file) file.close();
  static char madeDir[24] = "";   // last folder we mkdir'd; skip re-doing it (that scans /ESP1312) each open
  char date[12], dir[24];
  fileDated = gpsDate(date, sizeof date);
  if (fileDated) snprintf(dir, sizeof dir, "%s/%s", LOG_DIR, date);
  else           strlcpy(dir, LOG_DIR, sizeof dir);   // no date yet: root, moved into the day folder later
  if (strcmp(dir, madeDir) != 0) { SD.mkdir(LOG_DIR); SD.mkdir(dir); strlcpy(madeDir, dir, sizeof madeDir); }
  freePath(filePath, sizeof filePath, dir, 0);
  file = SD.open(filePath, FILE_WRITE);
  rows = 0;
  if (!file) { Serial.printf("[SD] open failed %s\n", filePath); return; }
  if (mode == WIGLE) {
    file.println("WigleWifi-1.6,appRelease=ESP1312,model=Cardputer,release=" FW_VERSION ",device=ESP32-S3,display=,board=M5Cardputer,brand=M5Stack");
    file.println("MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type");
  } else {
    file.println("time,type,mac,rssi,chan,enc,company_id,mfg_data,service_uuids,name,vendor,method,lat,lon,alt_m,sats,hdop");
  }
  file.flush();
  Serial.printf("[SD] logging to %s\n", filePath);
}

static void dateFile() {
  char date[12], dir[24], to[48];
  if (fileDated || !file || !gpsDate(date, sizeof date)) return;
  snprintf(dir, sizeof dir, "%s/%s", LOG_DIR, date);
  SD.mkdir(dir);
  // keep the number from log_N unless it's taken in the day folder, then count up from it
  int n = 0;
  const char* us = strrchr(filePath, '_');
  if (us) n = atoi(us + 1);
  freePath(to, sizeof to, dir, n);
  file.close();
  if (SD.rename(filePath, to)) strlcpy(filePath, to, sizeof filePath);
  file = SD.open(filePath, FILE_APPEND);
  fileDated = true;
  Serial.printf("[SD] renamed to %s\n", filePath);
}

// ---- one record in: dedupe, match, write -------------------------------------
static void logRec(const Rec& e) {
  const Sig* sig = matchSig(e.mac, e.company, e.mdata, e.uuids, e.name);
  bool threat = sig && strncmp(sig->method, "tracker", 7) != 0;   // trackers are logged, not alarmed
  if (mode == HUNT && !sig) return;

  bool   fix = gps.location.isValid();
  double lat = fix ? gps.location.lat() : 0, lon = fix ? gps.location.lng() : 0;
  uint32_t now = millis();

  // linear scan with round-robin eviction, fast enough at advert rates
  int i = 0;
  for (; i < seenN; i++) if (seen[i].kind == e.kind && strcmp(seen[i].mac, e.mac) == 0) break;
  if (i < seenN) {
    bool moved = fix && seen[i].lat != 0 && TinyGPSPlus::distanceBetween(seen[i].lat, seen[i].lon, lat, lon) > RELOG_M;
    if (!moved && now - seen[i].last < RELOG_MS) return;
  } else {
    if (seenN < SEEN_MAX) i = seenN++; else { i = seenNext; seenNext = (seenNext + 1) % SEEN_MAX; }
    strlcpy(seen[i].mac, e.mac, sizeof seen[i].mac); seen[i].kind = e.kind;
    if (e.kind == K_BLE) bleN++; else wifiN++;
    if (e.kind == K_PROBE) probeN++;
    if (threat) threats++;
  }
  seen[i].last = now; seen[i].lat = lat; seen[i].lon = lon;

  if (threat) {
    int h = 0;
    for (; h < hitsN; h++) if (hits[h].kind == e.kind && strcmp(hits[h].mac, e.mac) == 0) break;
    if (h == hitsN) {
      if (hitsN < HITS_MAX) hitsN++;
      else { h = 0; for (int k = 1; k < HITS_MAX; k++) if (hits[k].last < hits[h].last) h = k; }   // evict the oldest
      strlcpy(hits[h].mac, e.mac, sizeof hits[h].mac);
      strlcpy(hits[h].vendor, sig->vendor, sizeof hits[h].vendor);
      strlcpy(hits[h].method, sig->method, sizeof hits[h].method);
      hits[h].kind = e.kind;
    }
    hits[h].rssi = e.rssi; hits[h].last = now;
    snprintf(lastHit, sizeof lastHit, "%s %s %d dBm", sig->vendor, TYPE_NAME[e.kind], e.rssi);
    M5Cardputer.Speaker.tone(2200, 60);
    Serial.printf("[HIT] %s via %s mac=%s rssi=%d\n", sig->vendor, sig->method, e.mac, e.rssi);
  }
  if (!logging || !file) return;
  if (mode == WIGLE && e.kind == K_PROBE) return;   // a probe isn't a network, keep WiGLE files clean

  char t[20], la[14] = "", lo[14] = "", alt[10] = "", hdop[8] = "", sats[4] = "";
  gpsTime(t, sizeof t);
  if (fix) { snprintf(la, sizeof la, "%.6f", lat); snprintf(lo, sizeof lo, "%.6f", lon); }
  if (gps.altitude.isValid())   snprintf(alt,  sizeof alt,  "%.1f", gps.altitude.meters());
  if (gps.hdop.isValid())       snprintf(hdop, sizeof hdop, "%.1f", gps.hdop.value() / 100.0);
  if (gps.satellites.isValid()) snprintf(sats, sizeof sats, "%d",   (int)gps.satellites.value());
  bool ble = e.kind == K_BLE;

  if (mode == WIGLE)   // BLE rows: name as SSID, [BLE] auth, MfgrId = company ID
    file.printf("%s,%s,[%s],%s,%d,%d,%d,%s,%s,%s,%s,,%s,%s\n",
                e.mac, e.name, ble ? "BLE" : e.enc, t, e.chan, ble ? 0 : 2407 + e.chan * 5,
                e.rssi, la, lo, alt, hdop, e.company, ble ? "BLE" : "WIFI");
  else
    file.printf("%s,%s,%s,%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
                t, TYPE_NAME[e.kind], e.mac, e.rssi, e.chan, e.enc, e.company, e.mdata, e.uuids, e.name,
                sig ? sig->vendor : "", sig ? sig->method : "", la, lo, alt, sats, hdop);
  rows++;
}

// ---- WiFi (async sweep, drained in loop) ------------------------------------
static void wifiKick() {
  WiFi.scanDelete();
  WiFi.scanNetworks(/*async=*/true, /*hidden=*/true, /*passive=*/!active, WIFI_DWELL);
}

static void wifiPoll() {
  int n = WiFi.scanComplete();
  if (n == WIFI_SCAN_RUNNING) return;
  for (int i = 0; i < n; i++) {
    Rec e = {}; e.kind = K_WIFI;
    strlcpy(e.mac, WiFi.BSSIDstr(i).c_str(), sizeof e.mac); lowerStr(e.mac);
    strlcpy(e.name, WiFi.SSID(i).c_str(), sizeof e.name); csvSafe(e.name, sizeof e.name);
    e.rssi = WiFi.RSSI(i);
    e.chan = WiFi.channel(i);
    strlcpy(e.enc, encName(WiFi.encryptionType(i)), sizeof e.enc);
    logRec(e);
  }
  wifiKick();   // done or failed: next sweep picks up the current passive/active setting
}

// Frames straight off the air, while the scan above hops channels for us. Two things are
// worth keeping: probe requests (a client calling for its network, which catches gear that
// never beacons) and beacons carrying the ASTM F3411 Remote ID element
// (drones, DJI uses this form). Randomized MACs are dropped, which loses nearly every phone
// and keeps the hardware.
static void sniff(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  auto* p = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* f = p->payload;
  int len = p->rx_ctrl.sig_len - 4;                 // drop the FCS
  uint8_t sub = f[0] >> 4;
  if ((sub != 4 && sub != 8) || len < 24) return;   // 4 = probe request, 8 = beacon
  if (f[10] & 0x02) return;                         // locally administered = randomized

  const uint8_t* body = f + 24;
  int blen = len - 24, pos = (sub == 8) ? 12 : 0;   // beacons carry 12 fixed bytes before the elements
  char ssid[24] = "";
  bool rid = false;
  while (pos + 2 <= blen) {
    uint8_t id = body[pos], l = body[pos + 1];
    if (pos + 2 + l > blen) break;
    const uint8_t* v = body + pos + 2;
    if (id == 0 && l && l < sizeof ssid) {
      for (uint8_t i = 0; i < l; i++) ssid[i] = (v[i] >= 32 && v[i] < 127) ? (char)v[i] : '?';
      ssid[l] = 0;
    }
    if (id == 221 && l >= 4 && v[0] == 0xfa && v[1] == 0x0b && v[2] == 0xbc) rid = true;
    pos += 2 + l;
  }
  if (sub == 8 && !rid) return;                     // plain beacons already come from the scan

  Rec e = {};
  e.kind = rid ? K_RID : K_PROBE;
  snprintf(e.mac, sizeof e.mac, "%02x:%02x:%02x:%02x:%02x:%02x", f[10], f[11], f[12], f[13], f[14], f[15]);
  strlcpy(e.name, ssid, sizeof e.name); csvSafe(e.name, sizeof e.name);
  strlcpy(e.enc, rid ? "rid" : "probe", sizeof e.enc);
  if (rid) strlcpy(e.uuids, "0xfffa", sizeof e.uuids);   // same identifier as the BLE form
  e.rssi = p->rx_ctrl.rssi;
  e.chan = p->rx_ctrl.channel;
  push(e);
}

static void startSniff() {
  wifi_promiscuous_filter_t flt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
  esp_wifi_set_promiscuous_filter(&flt);
  esp_wifi_set_promiscuous_rx_cb(sniff);
  esp_wifi_set_promiscuous(true);
}

// ---- UI ---------------------------------------------------------------------
// The canvas is 8-bit, so keep tints on the RGB332 grid (R/G steps ~36, B steps 85) or they round to black
static const uint16_t BAR_BG = 0x212A;   // rgb(32,36,85) dark slate, header and footer
static const uint16_t AMBER  = 0xFE87;   // rgb(255,210,63) wordmark and logo

// body text is Font2 (16 px). big() switches to the 6x8 font scaled up, for the title and hero
static void big(bool on) {
  if (on) canvas.setFont(&fonts::Font0); else canvas.setFont(&fonts::Font2);
  canvas.setTextSize(on ? 1.5f : 1);
}

// crosshair logo, 13 px square from (x,y): matches the cap height of the header wordmark
static void logo(int x, int y, uint16_t c) {
  int cx = x + 6, cy = y + 6;
  canvas.drawCircle(cx, cy, 4, c);
  canvas.fillCircle(cx, cy, 1, c);
  canvas.drawFastVLine(cx, y, 3, c); canvas.drawFastVLine(cx, y + 10, 3, c);
  canvas.drawFastHLine(x, cy, 3, c); canvas.drawFastHLine(x + 10, cy, 3, c);
}

// Bigger crosshair, ~24 px, for the splash. The double ring reads bolder at this size.
static void bigLogo(int cx, int cy, uint16_t c) {
  canvas.drawCircle(cx, cy, 9, c);
  canvas.drawCircle(cx, cy, 10, c);
  canvas.fillCircle(cx, cy, 2, c);
  canvas.drawFastVLine(cx, cy - 15, 5, c); canvas.drawFastVLine(cx, cy + 11, 5, c);
  canvas.drawFastHLine(cx - 15, cy, 5, c); canvas.drawFastHLine(cx + 11, cy, 5, c);
}

// small WiFi glyph: a dot with arcs fanning up, ~13 wide x 11 tall from (x,y) top-left
static void wifiIcon(int x, int y, uint16_t c) {
  int cx = x + 6, cy = y + 9;
  canvas.fillCircle(cx, cy, 1, c);
  canvas.fillArc(cx, cy, 3, 4, 215, 325, c);   // 270 = up on this panel; fan over the dot
  canvas.fillArc(cx, cy, 6, 7, 215, 325, c);   // wider gaps read cleaner than three tight arcs
  canvas.fillArc(cx, cy, 9, 10, 215, 325, c);
}
// small Bluetooth rune: spine + two right triangles + two crossing diagonals, ~7 wide x 11 tall
static void btIcon(int x, int y, uint16_t c) {
  int cx = x + 3, t = y, b = y + 11, rx = x + 6, lx = x, hi = y + 3, lo = y + 8;
  canvas.drawLine(cx, t, cx, b, c);      // spine
  canvas.drawLine(cx, t, rx, hi, c);     // top -> upper-right vertex
  canvas.drawLine(cx, b, rx, lo, c);     // bottom -> lower-right vertex
  canvas.drawLine(lx, hi, rx, lo, c);    // upper-left -> lower-right vertex (through center)
  canvas.drawLine(lx, lo, rx, hi, c);    // lower-left -> upper-right vertex (through center)
}
// small battery: outlined body + nub, filled proportional to charge
static void batteryIcon(int x, int y, int pct, uint16_t c) {
  canvas.drawRect(x, y, 16, 9, c);            // body
  canvas.fillRect(x + 16, y + 2, 2, 5, c);    // + terminal nub
  int w = (pct * 14) / 100;                   // 14 px of inner fill
  if (w > 0) canvas.fillRect(x + 1, y + 1, w, 7, c);
}
// small SD card: body with a notched top-right corner; slashed when absent
static void sdIcon(int x, int y, uint16_t c, bool slash) {
  canvas.drawLine(x, y, x + 6, y, c);            // top, up to the notch
  canvas.drawLine(x + 6, y, x + 10, y + 4, c);   // clipped corner
  canvas.drawLine(x + 10, y + 4, x + 10, y + 13, c);
  canvas.drawLine(x, y + 13, x + 10, y + 13, c);
  canvas.drawLine(x, y, x, y + 13, c);
  if (slash) canvas.drawLine(x, y + 13, x + 10, y, c);   // absent: strike through
}

// Draw a footer hint word by word. Keys (uppercase/symbols) stay bright and the
// lowercase labels after them go dim, so the keys read first. Preserves the
// original spacing (double gaps between groups).
static void drawHint(const char* h) {
  int x = 4; char word[24]; int n = 0;
  auto flush = [&]() {
    if (!n) return;
    word[n] = 0;
    // ; and . are the Cardputer's up/down arrow keys, so draw them as arrow glyphs
    if (n == 1 && (word[0] == ';' || word[0] == '.')) {
      int ay = 121, ah = 8, aw = 7;
      if (word[0] == ';') canvas.fillTriangle(x, ay + ah, x + aw, ay + ah, x + aw / 2, ay, TFT_LIGHTGREY);       // up
      else                canvas.fillTriangle(x, ay, x + aw, ay, x + aw / 2, ay + ah, TFT_LIGHTGREY);            // down
      x += aw; n = 0; return;
    }
    bool label = false;
    for (int i = 0; i < n; i++) if (word[i] >= 'a' && word[i] <= 'z') { label = true; break; }
    canvas.setTextColor(label ? TFT_DARKGREY : TFT_LIGHTGREY, BAR_BG);
    canvas.drawString(word, x, 118);
    x += canvas.textWidth(word); n = 0;
  };
  for (const char* p = h; ; p++) {
    if (*p == ' ' || !*p) { flush(); if (!*p) break; x += canvas.textWidth(" "); }
    else if (n < 22) word[n++] = *p;
  }
}

static void footer(const char* hint) {
  canvas.fillRect(0, 117, 240, 18, BAR_BG);
  drawHint(hint);
  if (!sdOk) {
    sdIcon(224, 120, TFT_RED, true);                 // absent: red, slashed
  } else {
    sdIcon(224, 120, TFT_DARKGREY, false);           // mounted
    if (!logging) {                                  // paused: two orange bars, clears the hint
      canvas.fillRect(210, 120, 3, 11, TFT_ORANGE);
      canvas.fillRect(216, 120, 3, 11, TFT_ORANGE);
    } else {                                         // recording: a blinking red dot
      if ((millis() / 700) % 2) canvas.fillCircle(214, 126, 4, TFT_RED);
      else                      canvas.drawCircle(214, 126, 4, TFT_RED);
    }
  }
}

static void header() {
  canvas.fillSprite(TFT_BLACK);
  canvas.fillRect(0, 0, 240, 22, BAR_BG);
  logo(4, 4, AMBER);   // rows 4-16, level with the wordmark caps
  canvas.setTextColor(AMBER, BAR_BG); canvas.setFont(&fonts::Font0); canvas.setTextSize(1.75f);
  canvas.drawString("ESP1312", 22, 4); big(false);
  // Hold the shown level until the raw reading moves >=2%, so ADC ripple under radio
  // load doesn't flicker it between adjacent percents.
  static int shownBat = -1;
  int raw = M5Cardputer.Power.getBatteryLevel();
  if (shownBat < 0 || raw <= shownBat - 2 || raw >= shownBat + 2) shownBat = raw;
  int bat = shownBat;
  uint16_t bc = bat > 50 ? TFT_GREEN : bat > 20 ? TFT_ORANGE : TFT_RED;
  batteryIcon(182, 6, bat, bc);
  char v[8]; snprintf(v, sizeof v, "%d%%", bat);
  canvas.setTextColor(bc, BAR_BG); canvas.drawString(v, 204, 3);
  // version, dim, tucked right after the title so it reads as part of the wordmark
  canvas.setFont(&fonts::Font0); canvas.setTextSize(1);
  canvas.setTextColor(TFT_DARKGREY, BAR_BG); canvas.drawString("v" FW_VERSION, 99, 10);   // bottom-aligned with the title, tucked in close
  big(false);   // restore Font2 for the body rows the screens draw next
}



static void drawHome() {
  char v[40];
  header();
  if (threats) {
    canvas.setTextColor(TFT_RED, TFT_BLACK); big(true);
    snprintf(v, sizeof v, "%u THREAT%s", (unsigned)threats, threats > 1 ? "S" : ""); canvas.drawString(v, 12, 32);
    big(false); canvas.setTextColor(TFT_ORANGE, TFT_BLACK); canvas.drawString(lastHit, 12, 48);
  } else {
    canvas.setTextColor(TFT_GREEN, TFT_BLACK); big(true); canvas.drawString("CLEAR", 12, 32);
    big(false); canvas.setTextColor(TFT_LIGHTGREY, TFT_BLACK); canvas.drawString("no threats in range", 12, 48);
  }
  canvas.drawFastHLine(4, 70, 232, canvas.color565(47, 54, 64));

  bool fix = gps.location.isValid();
  canvas.fillCircle(11, 84, 4, fix ? TFT_GREEN : TFT_ORANGE);
  canvas.setTextColor(fix ? TFT_GREEN : TFT_ORANGE, TFT_BLACK);
  canvas.drawString(fix ? "GPS LOCK" : "GPS ...", 20, 76);
  if (fix) {
    snprintf(v, sizeof v, "%d sats", (int)gps.satellites.value());
    canvas.setTextColor(TFT_LIGHTGREY, TFT_BLACK); canvas.drawString(v, 20, 94);
  } else {
    canvas.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    snprintf(v, sizeof v, "nmea %lu ok %lu", (unsigned long)gps.charsProcessed(), (unsigned long)gps.passedChecksum());
    canvas.drawString(v, 20, 94);
  }

  snprintf(v, sizeof v, "%s (%s)", MODE_NAME[mode], active ? "probe" : "passive");
  canvas.setTextColor(TFT_CYAN, TFT_BLACK); canvas.drawString(v, 132, 76);
  canvas.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
  // colored WiFi and Bluetooth glyphs with their live counts (icons read faster than W/B labels)
  wifiIcon(132, 95, canvas.color565(90, 190, 255));   // light blue
  snprintf(v, sizeof v, "%u", (unsigned)wifiN); canvas.setTextColor(TFT_LIGHTGREY, TFT_BLACK); canvas.drawString(v, 152, 94);
  btIcon(198, 95, canvas.color565(0, 100, 255));      // Bluetooth blue
  snprintf(v, sizeof v, "%u", (unsigned)bleN); canvas.drawString(v, 208, 94);
  footer("TAB info  M mode  P pause");
}

static void row(int y, const char* label, uint16_t col, const char* value) {
  canvas.setTextColor(TFT_DARKGREY, TFT_BLACK); canvas.drawString(label, 4, y);
  canvas.setTextColor(col, TFT_BLACK);         canvas.drawString(value, 56, y);
}

static void drawDetails() {
  char v[40];
  header();
  snprintf(v, sizeof v, "%s  (%s)", MODE_NAME[mode], MODE_HINT[mode]);
  row(29, "mode", TFT_WHITE, v);
  row(45, "scan", active ? TFT_ORANGE : TFT_CYAN, active ? "active (probe)" : "passive (listen)");
  bool fix = gps.location.isValid();
  if (fix) snprintf(v, sizeof v, "%.5f, %.5f", gps.location.lat(), gps.location.lng());
  else     snprintf(v, sizeof v, "no fix  baud %d  ok %lu", BAUDS[baudIdx], (unsigned long)gps.passedChecksum());
  row(61, "gps", fix ? TFT_GREEN : TFT_ORANGE, v);
  snprintf(v, sizeof v, "%d sat  hdop %.1f", gps.satellites.isValid() ? (int)gps.satellites.value() : 0,
           gps.hdop.isValid() ? gps.hdop.value() / 100.0 : 0.0);
  row(77, "sats", TFT_WHITE, v);
  const char* base = strrchr(filePath, '/'); base = base ? base + 1 : filePath;   // just log_N.csv; the date is the folder
  snprintf(v, sizeof v, "%s  %u rows", sdOk ? base : "no SD", (unsigned)rows);
  row(93, "file", sdOk ? TFT_LIGHTGREY : TFT_RED, v);
  footer("TAB threats  S scan  N new");
}

// newest first, three per page, ; and . scroll
static void drawThreats() {
  char v[40];
  header();
  int order[HITS_MAX];
  for (int i = 0; i < hitsN; i++) order[i] = i;
  uint32_t now = millis();   // sort by age, not raw timestamp, so it survives the millis() wrap
  std::sort(order, order + hitsN, [now](int a, int b) { return now - hits[a].last < now - hits[b].last; });
  int pages = hitsN ? (hitsN + 2) / 3 : 1;
  if (hitScroll >= pages) hitScroll = pages - 1;
  if (hitScroll < 0) hitScroll = 0;

  if (!hitsN) { canvas.setTextColor(TFT_DARKGREY, TFT_BLACK); canvas.drawString("no threats detected", 12, 40); }
  int y = 26;
  for (int i = hitScroll * 3; i < hitsN && i < hitScroll * 3 + 3; i++) {
    Hit& h = hits[order[i]];
    uint32_t age = (millis() - h.last) / 1000;
    if (age < 60) snprintf(v, sizeof v, "%s  %s  %d dBm  %lus", h.vendor, TYPE_NAME[h.kind], h.rssi, (unsigned long)age);
    else          snprintf(v, sizeof v, "%s  %s  %d dBm  %lum", h.vendor, TYPE_NAME[h.kind], h.rssi, (unsigned long)age / 60);
    canvas.setTextColor(age < 30 ? TFT_RED : TFT_ORANGE, TFT_BLACK); canvas.drawString(v, 8, y);
    snprintf(v, sizeof v, "%s  %s", h.mac, h.method);
    canvas.setFont(&fonts::Font0); canvas.setTextColor(TFT_DARKGREY, TFT_BLACK); canvas.drawString(v, 8, y + 17);
    canvas.setFont(&fonts::Font2);
    y += 30;
  }
  snprintf(v, sizeof v, "TAB home  ; . page %d/%d", hitScroll + 1, pages);
  footer(v);
}

// ---- keys -------------------------------------------------------------------
static void handleKey(char c) {
  switch (c) {
    case 'm': mode = Mode((mode + 1) % 3); active = (mode == HUNT); startBle(); openFile(); break;
    case 's': active = !active; startBle(); break;   // WiFi picks it up on its next sweep
    case 'p': logging = !logging; break;
    case 'n': openFile(); break;
    case ';': hitScroll--; break;   // the Cardputer's up arrow
    case '.': hitScroll++; break;   // down arrow
  }
}

static void keys() {
  if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed()) return;
  lastKey = millis();
  if (asleep) { asleep = false; M5Cardputer.Display.setBrightness(brightness); return; }   // wake only
  auto& st = M5Cardputer.Keyboard.keysState();
  if (st.tab) view = (view + 1) % 3;
  for (char c : st.word) handleKey(c);
}

// Stream a log over serial. No name means the one currently open.
static void dumpFile(const char* name) {
  char path[64];
  if (name && *name) snprintf(path, sizeof path, "%s/%s", LOG_DIR, name);
  else { if (!file) return; strlcpy(path, filePath, sizeof path); }
  bool current = strcmp(path, filePath) == 0;
  if (current && file) file.close();
  File r = SD.open(path, FILE_READ);
  Serial.printf("[DUMP] %s\n", path);
  while (r && r.available()) Serial.write(r.read());
  r.close();
  Serial.println("[END]");
  if (current) file = SD.open(filePath, FILE_APPEND);
}

// l: list the log folder. x: delete everything in it except the open file. Serial only, on purpose.
static void walkDir(const char* path, bool wipe) {   // recurse the day folders
  File dir = SD.open(path);
  char full[64];
  for (File f = dir.openNextFile(); f; f = dir.openNextFile()) {
    bool isDir = f.isDirectory();
    snprintf(full, sizeof full, "%s/%s", path, f.name());
    uint32_t sz = f.size(); f.close();
    if (isDir) { walkDir(full, wipe); if (wipe) SD.rmdir(full); }   // wipe: empty the day folder, then drop it
    else if (!wipe) Serial.printf("%s %u\n", full, (unsigned)sz);
    else if (strcmp(full, filePath) != 0) SD.remove(full);
  }
}

static void draw() {
  if (view == 1) drawDetails(); else if (view == 2) drawThreats(); else drawHome();
}

// g: send the last drawn frame (240x135, one RGB332 byte per pixel) for a screenshot. v: next view.
// The canvas is at most 300 ms old, and during the splash it holds the splash.
static void grabScreen() {
  Serial.println("[IMG] 240 135");
  Serial.write((const uint8_t*)canvas.getBuffer(), 240 * 135);
  Serial.println("[END]");
}

static void serialKeys() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == 'd') dumpFile(nullptr);
    else if (c == 'g') grabScreen();
    else if (c == 'v') view = (view + 1) % 3;
    else if (c == 'f') { String n = Serial.readStringUntil('\n'); n.trim(); dumpFile(n.c_str()); }   // f<name>
    else if (c == 'h') {   // the threats table
      for (int i = 0; i < hitsN; i++)
        Serial.printf("%s %s %s %d %lus %s\n", hits[i].vendor, TYPE_NAME[hits[i].kind], hits[i].mac, hits[i].rssi,
                      (unsigned long)((millis() - hits[i].last) / 1000), hits[i].method);
      Serial.println("[END]");
    }
    else if (c == 'l') { walkDir(LOG_DIR, false); Serial.println("[END]"); }
    else if (c == 'x') { walkDir(LOG_DIR, true);  Serial.println("[WIPED]"); }
    else if (c == 'G') Serial.printf("[gps] baud=%d nmea=%lu ok=%lu sats=%d fix=%d\n", BAUDS[baudIdx],
      (unsigned long)gps.charsProcessed(), (unsigned long)gps.passedChecksum(),
      gps.satellites.isValid() ? (int)gps.satellites.value() : -1, gps.location.isValid());
    else handleKey(c);
  }
}

// ---- boot hero --------------------------------------------------------------
// The whole splash in one frame so the early boot frame and the dwell share it.
// tick advances the trailing dots; draws to the canvas, caller pushes.
static void drawSplash() {
  canvas.fillSprite(TFT_BLACK);
  bigLogo(120, 22, AMBER);   // raised, clear of the wordmark below
  canvas.setTextDatum(top_center);
  canvas.setTextColor(AMBER, TFT_BLACK);
  canvas.setFont(&fonts::Font0); canvas.setTextSize(3);
  canvas.drawString("ESP1312", 120, 44);                 // ~126 px wide, centered
  // tagline on its own solid band so it reads as a distinct element, not stacked text
  canvas.fillRect(0, 74, 240, 20, BAR_BG);
  canvas.setFont(&fonts::Font2); canvas.setTextSize(1); canvas.setTextDatum(top_left);
  int wa = canvas.textWidth("counter "), wb = canvas.textWidth("ESP");
  int sx = 120 - (wa + wb + canvas.textWidth("ionage")) / 2;
  canvas.setTextColor(TFT_LIGHTGREY, BAR_BG); canvas.drawString("counter ", sx, 77);
  canvas.setTextColor(AMBER, BAR_BG);         canvas.drawString("ESP", sx + wa, 77);
  canvas.setTextColor(TFT_LIGHTGREY, BAR_BG); canvas.drawString("ionage", sx + wa + wb, 77);
  // start prompt: driving waits for a keypress
  canvas.setTextDatum(top_center); canvas.setTextColor(canvas.color565(120, 200, 255), TFT_BLACK);
  canvas.drawString("press any key to start", 120, 101);   // centered in the gap between the band and the version
  // version, dim, at the bottom
  canvas.setFont(&fonts::Font0); canvas.setTextSize(1);
  canvas.setTextColor(TFT_DARKGREY, TFT_BLACK); canvas.drawString("v" FW_VERSION, 120, 124);
  canvas.setTextDatum(top_left);
  big(false);
}

// Boot hero, then wait for a key before driving. The hardware is already up by the
// time this shows, so it's a deliberate "ready" gate, not a loading screen.
static void splash() {
  drawSplash();
  canvas.pushSprite(&M5Cardputer.Display, 0, 0);
  for (;;) {
    M5Cardputer.update();
    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) break;
    serialKeys();   // so g can grab the splash
    delay(20);
  }
  lastKey = millis();   // don't count boot dwell toward the screen-off timer
}

// ---- setup / loop -----------------------------------------------------------
void setup() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Display.setRotation(1);
  Serial.begin(115200);
  Serial.printf("[ESP1312] firmware v%s\n", FW_VERSION);
  canvas.setColorDepth(8);        // 16-bit doesn't fit next to WiFi + NimBLE
  canvas.createSprite(240, 135);
  canvas.setFont(&fonts::Font2);
  brightness = M5Cardputer.Display.getBrightness();

  // Hero up front so the ~1-2 s of SD/GPS/radio init isn't a black screen; splash()
  // shows the same frame and waits for a key once init is done.
  drawSplash();
  canvas.pushSprite(&M5Cardputer.Display, 0, 0);

  // ADV: GPIO5 must be high or the card never answers CMD0. Keep 4 MHz.
  pinMode(5, OUTPUT);
  digitalWrite(5, HIGH);
  delay(250);
  static SPIClass sdSPI(HSPI);
  sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  delay(20);
  for (int i = 0; i < 4 && !sdOk; i++) {
    sdOk = SD.begin(SD_CS, sdSPI, 4000000UL, "/sd", 5) && SD.cardType() != CARD_NONE;
    if (!sdOk) { SD.end(); delay(120); }
  }
  Serial.printf("[SD] %s type=%d\n", sdOk ? "mounted" : "FAILED", (int)SD.cardType());

  // A software reset (how bmorcelli's Launcher boots the app) leaves UART1 and the GPS
  // pins in a state HardwareSerial.begin() doesn't fully clear, so RX reads nothing. A
  // hardware reset doesn't. Reset the peripheral and pins to default first, once.
  periph_module_reset(PERIPH_UART1_MODULE);
  gpio_reset_pin((gpio_num_t)GPS_RX);
  gpio_reset_pin((gpio_num_t)GPS_TX);
  gpsBegin();
  NimBLEDevice::init("");
  startBle();
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  startSniff();
  wifiKick();
  Serial.printf("[mem] free=%u dma=%u\n", ESP.getFreeHeap(), heap_caps_get_free_size(MALLOC_CAP_DMA));
  openFile();
  splash();
}

void loop() {
  M5Cardputer.update();
  keys();
  serialKeys();
  while (gpsSerial.available()) gps.encode(gpsSerial.read());
  gpsAutoBaud();
  dateFile();
  wifiPoll();

  for (int n = 0; n < 64; n++) {
    Rec e;
    portENTER_CRITICAL(&rMux);
    bool have = rTail != rHead;
    if (have) { e = ring[rTail]; rTail = (rTail + 1) % RING; }
    portEXIT_CRITICAL(&rMux);
    if (!have) break;
    logRec(e);
  }

  static uint32_t tFlush = 0, tUi = 0, tMem = 0;
  if (file && millis() - tFlush > 1500) { file.flush(); tFlush = millis(); }
  if (millis() - tMem > 30000) {
    Serial.printf("[mem] free=%u min=%u wifi=%u probe=%u ble=%u rows=%u\n", ESP.getFreeHeap(), ESP.getMinFreeHeap(), wifiN, probeN, bleN, rows);
    tMem = millis();
  }
  if (!asleep && millis() - lastKey > SCREEN_OFF_MS) { asleep = true; M5Cardputer.Display.setBrightness(0); }
  if (!asleep && millis() - tUi > 300) {
    draw();
    canvas.pushSprite(&M5Cardputer.Display, 0, 0);   // pass the display, the parent stored by the ctor isn't reliable
    tUi = millis();
  }
}
