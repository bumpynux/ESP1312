// Surveillance-vendor signature table. Each row flags a device by MAC OUI, BLE company ID,
// service UUID, manufacturer data, or advertised name. The matcher compares the first three
// bytes of a MAC, so only 24-bit OUIs go here.
//
// OUI rows need a public MAC (in-car routers and dash cams use one, most phones and body cams
// randomize), which is why company IDs, UUIDs and names carry more weight on BLE.
//
// Where each row came from and how far it's trusted lives in SIGNATURES.md, beside this file.
// Corrections welcome, open a PR with where you saw it.
#pragma once
#include <stdio.h>
#include <string.h>
#include <ctype.h>

enum SigType { SIG_OUI, SIG_COMPANY, SIG_MFG, SIG_UUID16, SIG_UUID128, SIG_NAME };

struct Sig {
  SigType     type;
  const char* value;   // lowercase: "aa:bb:cc" | "034d" | "004c12" (company + data prefix) | "fc81" | name substring
  const char* vendor;
  const char* method;
};

static const Sig SIGS[] = {
  // ---- law enforcement ----
  // AXON: body cameras, Taser Signal, Fleet in-car
  { SIG_COMPANY, "034d",        "AXON",   "ble_company_id"   },
  { SIG_UUID16,  "fc81",        "AXON",   "ble_service_uuid" },
  { SIG_OUI,     "00:25:df",    "AXON",   "ble_oui"          },
  // Body cams in the field advertised this 128-bit UUID and no company ID.
  // The hex spells AXJANUSBWCDEVICE: Axon, a codename, body-worn camera, device.
  { SIG_UUID128, "41584a41-4e55-5342-5743-444556494345", "AXON", "ble_service_uuid" },
  // WATCHGUARD VIDEO (Motorola Solutions): V300/V700 body cams, 4RE in-car video
  { SIG_OUI,     "00:1d:96",    "WATCHGUARD", "wifi_oui"     },
  // DIGITAL ALLY: FirstVu body cams, DVM in-car video
  { SIG_OUI,     "00:23:bd",    "DIGITALALLY", "wifi_oui"    },
  // GENETEC: AutoVu SharpV/SharpZ ALPR cameras (fixed and vehicle mounted)
  { SIG_OUI,     "00:bf:15",    "GENETEC", "wifi_oui"        },
  { SIG_OUI,     "0c:bf:15",    "GENETEC", "wifi_oui"        },
  // CRADLEPOINT: in-vehicle LTE routers, the WiFi AP inside most cruisers. Weak on its
  // own, buses, ambulances and retail use them too, but moving with you it's a good tell.
  { SIG_OUI,     "00:30:44",    "CRADLEPOINT", "wifi_oui"    },
  { SIG_OUI,     "00:e0:1c",    "CRADLEPOINT", "wifi_oui"    },
  // ---- deployed surveillance ----
  // DRONES, any make: FAA Remote ID broadcast. Police units (Skydio X10, BRINC) included.
  { SIG_UUID16,  "fffa",        "DRONE",  "remote_id"        },
  // FLOCK SAFETY: battery modules and Raven gunshot sensors advertise these names and UUIDs
  { SIG_NAME,    "penguin",     "FLOCK",  "ble_name"         },
  { SIG_NAME,    "pigvision",   "FLOCK",  "ble_name"         },
  { SIG_NAME,    "fs ext battery", "FLOCK", "ble_name"       },
  { SIG_UUID16,  "3100",        "FLOCK",  "ble_service_uuid" },
  { SIG_UUID16,  "3200",        "FLOCK",  "ble_service_uuid" },
  { SIG_UUID16,  "3300",        "FLOCK",  "ble_service_uuid" },
  { SIG_UUID16,  "3400",        "FLOCK",  "ble_service_uuid" },
  { SIG_UUID16,  "3500",        "FLOCK",  "ble_service_uuid" },
  // ---- intrusive wearables and trackers ----
  // META: Ray-Ban / Oakley smart glasses. 0x01ab is Meta Platforms itself, seen with 0xfd5f
  // on glasses in the wild.
  { SIG_COMPANY, "0d53",        "META",   "ble_company_id"   },
  { SIG_COMPANY, "01ab",        "META",   "ble_company_id"   },
  { SIG_UUID16,  "fd5f",        "META",   "ble_service_uuid" },
  { SIG_NAME,    "ray-ban",     "META",   "ble_name"         },
  { SIG_NAME,    "wayfarer",    "META",   "ble_name"         },
  { SIG_NAME,    "oakley meta", "META",   "ble_name"         },
  { SIG_OUI,     "7c:2a:9e",    "META",   "ble_oui"          },
  { SIG_OUI,     "cc:66:0a",    "META",   "ble_oui"          },
  { SIG_OUI,     "f4:03:43",    "META",   "ble_oui"          },
  { SIG_OUI,     "5c:e9:1e",    "META",   "ble_oui"          },
  { SIG_OUI,     "98:59:49",    "META",   "ble_oui"          },
  // FLOCK SAFETY: their own WiFi OUI, the 'Flock-XXXX' provisioning SSID, and the Xuntong
  // company ID their battery modules and Raven sensors advertise
  { SIG_OUI,     "b4:1e:52",    "FLOCK",  "wifi_oui"         },
  { SIG_NAME,    "flock",       "FLOCK",  "wifi_ssid"        },
  { SIG_COMPANY, "09c8",        "FLOCK",  "ble_company_id"   },
  // TRACKERS: AirTag and other Find My tags (Apple type 0x12), Tile, Samsung SmartTag.
  // Usually someone's keys, so the "tracker_" method prefix keeps these out of the chirp
  // and threat count. They're still tagged in the log, so one that travels with you stands out.
  { SIG_MFG,     "004c12",      "FINDMY", "tracker_mfg_data"     },
  { SIG_COMPANY, "00c7",        "TILE",   "tracker_company_id"   },
  { SIG_UUID16,  "feed",        "TILE",   "tracker_service_uuid" },
  { SIG_UUID16,  "feec",        "TILE",   "tracker_service_uuid" },
  { SIG_UUID16,  "fd5a",        "SMARTTAG", "tracker_service_uuid" },
  // ---- home security ----
  // RING: doorbells, stick-up cams
  { SIG_OUI,     "18:7f:88",    "RING",   "ble_oui"          },
  { SIG_OUI,     "24:2b:d6",    "RING",   "ble_oui"          },
  { SIG_OUI,     "34:3e:a4",    "RING",   "ble_oui"          },
  { SIG_OUI,     "54:e0:19",    "RING",   "ble_oui"          },
  { SIG_OUI,     "5c:47:5e",    "RING",   "ble_oui"          },
  { SIG_OUI,     "64:9a:63",    "RING",   "ble_oui"          },
  { SIG_OUI,     "90:48:6c",    "RING",   "ble_oui"          },
  { SIG_OUI,     "9c:76:13",    "RING",   "ble_oui"          },
  { SIG_OUI,     "ac:9f:c3",    "RING",   "ble_oui"          },
  { SIG_OUI,     "c4:db:ad",    "RING",   "ble_oui"          },
  { SIG_OUI,     "cc:3b:fb",    "RING",   "ble_oui"          },
  // SIMPLISAFE: base stations, cameras, doorbells
  { SIG_OUI,     "f8:51:28",    "SIMPLISAFE", "wifi_oui"     },
  // WYZE: cameras, doorbells (a4:da:22:2 is a 28-bit block, so it's left out)
  { SIG_OUI,     "2c:aa:8e",    "WYZE",   "wifi_oui"         },
  { SIG_OUI,     "7c:78:b2",    "WYZE",   "wifi_oui"         },
  { SIG_OUI,     "80:48:2c",    "WYZE",   "wifi_oui"         },
  { SIG_OUI,     "d0:3f:27",    "WYZE",   "wifi_oui"         },
  { SIG_OUI,     "f0:c8:8b",    "WYZE",   "wifi_oui"         },
  // BLINK (Amazon): cameras, doorbells, sync modules
  { SIG_OUI,     "3c:a0:70",    "BLINK",  "wifi_oui"         },
  { SIG_OUI,     "70:ad:43",    "BLINK",  "wifi_oui"         },
  { SIG_OUI,     "74:13:48",    "BLINK",  "wifi_oui"         },
  { SIG_OUI,     "74:ab:93",    "BLINK",  "wifi_oui"         },
  { SIG_OUI,     "c8:19:d8",    "BLINK",  "wifi_oui"         },
  { SIG_OUI,     "f0:74:c1",    "BLINK",  "wifi_oui"         },
  // ARLO: cameras, doorbells, base stations
  { SIG_OUI,     "48:62:64",    "ARLO",   "wifi_oui"         },
  { SIG_OUI,     "a4:11:62",    "ARLO",   "wifi_oui"         },
  { SIG_OUI,     "fc:9c:98",    "ARLO",   "wifi_oui"         },
  // NEST (Google): cameras, doorbells, thermostats, speakers share these
  { SIG_OUI,     "18:b4:30",    "NEST",   "wifi_oui"         },
  { SIG_OUI,     "64:16:66",    "NEST",   "wifi_oui"         },
  // ---- drones ----
  // DJI / PARROT / SKYDIO
  { SIG_OUI,     "0c:9a:e6",    "DJI",    "ble_oui"          },
  { SIG_OUI,     "8c:58:23",    "DJI",    "ble_oui"          },
  { SIG_OUI,     "04:a8:5a",    "DJI",    "ble_oui"          },
  { SIG_OUI,     "58:b8:58",    "DJI",    "ble_oui"          },
  { SIG_OUI,     "e4:7a:2c",    "DJI",    "ble_oui"          },
  { SIG_OUI,     "60:60:1f",    "DJI",    "ble_oui"          },
  { SIG_OUI,     "48:1c:b9",    "DJI",    "ble_oui"          },
  { SIG_OUI,     "34:d2:62",    "DJI",    "ble_oui"          },
  { SIG_OUI,     "00:12:1c",    "PARROT", "ble_oui"          },
  { SIG_OUI,     "00:26:7e",    "PARROT", "ble_oui"          },
  { SIG_OUI,     "90:03:b7",    "PARROT", "ble_oui"          },
  { SIG_OUI,     "90:3a:e6",    "PARROT", "ble_oui"          },
  { SIG_OUI,     "a0:14:3d",    "PARROT", "ble_oui"          },
  { SIG_OUI,     "38:1d:14",    "SKYDIO", "ble_oui"          },
};

// Make a radio-supplied string safe as one CSV cell of size n. Field separators become spaces,
// and a leading = + - @ gets a quote in front so spreadsheets read the cell as text, not a formula.
static void csvSafe(char* s, size_t n) {
  for (char* c = s; *c; c++) if (*c == ',' || *c == '"' || *c == '\n' || *c == '\r') *c = ' ';
  if (*s && strchr("=+-@", *s)) { memmove(s + 1, s, n - 2); s[n - 1] = 0; *s = '\''; }
}

// True if text contains sub, ignoring case.
static bool hasLower(const char* text, const char* sub) { return strcasestr(text, sub) != nullptr; }

// First matching signature or nullptr. mac/company/mdata/uuids must already be lowercase.
// uuids is a space-separated list where 16-bit ones look like "0xfc81".
static const Sig* matchSig(const char* mac, const char* company, const char* mdata, const char* uuids, const char* name) {
  char cm[16], u16[8];
  snprintf(cm, sizeof cm, "%s%s", company, mdata);
  for (const Sig& s : SIGS) {
    bool hit = false;
    switch (s.type) {
      case SIG_COMPANY: hit = *company && strcmp(company, s.value) == 0;                     break;
      case SIG_MFG:     hit = *company && strncmp(cm, s.value, strlen(s.value)) == 0;         break;
      case SIG_UUID16:  snprintf(u16, sizeof u16, "0x%s", s.value); hit = hasLower(uuids, u16); break;
      case SIG_UUID128: hit = *uuids && hasLower(uuids, s.value);                             break;
      case SIG_NAME:    hit = *name && hasLower(name, s.value);                               break;
      case SIG_OUI:     hit = strncmp(mac, s.value, 8) == 0;                                  break;
    }
    if (hit) return &s;
  }
  return nullptr;
}
