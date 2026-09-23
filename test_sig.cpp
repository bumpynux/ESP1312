// Host-side check of the signature matcher and CSV escaping.  Run:  c++ -std=c++17 -Isrc test_sig.cpp && ./a.out
#include <assert.h>
#include <stdio.h>
#include "signatures.h"

int main() {
  const Sig* s;
  s = matchSig("5a:11:22:33:44:55", "034d", "", "", "");                assert(s && !strcmp(s->vendor, "AXON"));
  s = matchSig("5a:11:22:33:44:55", "", "", "0xfc81 0x180f", "");       assert(s && !strcmp(s->method, "ble_service_uuid"));
  s = matchSig("b4:1e:52:aa:bb:cc", "", "", "", "");                     assert(s && !strcmp(s->vendor, "FLOCK"));
  s = matchSig("5a:11:22:33:44:55", "", "", "", "Flock-2f3a");           assert(s && !strcmp(s->method, "wifi_ssid"));
  s = matchSig("5a:11:22:33:44:55", "", "", "", "FS Ext Battery");       assert(s && !strcmp(s->vendor, "FLOCK"));
  s = matchSig("5a:11:22:33:44:55", "", "", "", "Ray-Ban Meta");         assert(s && !strcmp(s->vendor, "META"));
  s = matchSig("f8:51:28:aa:bb:cc", "", "", "", "");                     assert(s && !strcmp(s->vendor, "SIMPLISAFE"));
  s = matchSig("00:1d:96:aa:bb:cc", "", "", "", "");                     assert(s && !strcmp(s->vendor, "WATCHGUARD"));
  s = matchSig("5a:11:22:33:44:55", "", "", "0xfffa", "");               assert(s && !strcmp(s->vendor, "DRONE"));
  s = matchSig("5a:11:22:33:44:55", "", "", "41584a41-4e55-5342-5743-444556494345", ""); assert(s && !strcmp(s->vendor, "AXON"));
  s = matchSig("5a:11:22:33:44:55", "01ab", "", "0xfd5f", "");           assert(s && !strcmp(s->vendor, "META"));
  s = matchSig("5a:11:22:33:44:55", "004c", "1219aa", "", "");           assert(s && !strcmp(s->vendor, "FINDMY"));
  s = matchSig("5a:11:22:33:44:55", "004c", "0215aa", "", "");           assert(!s);   // iBeacon, not a tag
  s = matchSig("5a:11:22:33:44:55", "", "", "0xfd5a", "");               assert(s && !strcmp(s->vendor, "SMARTTAG"));
  s = matchSig("5a:11:22:33:44:55", "", "", "6ba1b218-fffa-461f-9fa8-5dcae273", ""); assert(!s);   // no 16-bit match inside a 128-bit UUID
  s = matchSig("5a:11:22:33:44:55", "004c", "", "0x180f", "iPhone");     assert(!s);
  s = matchSig("5a:11:22:33:44:55", "", "", "", "");                     assert(!s);

  char b[24];
  strcpy(b, "=cmd|' /c calc'!A0");      csvSafe(b, sizeof b); assert(!strcmp(b, "'=cmd|' /c calc'!A0"));
  strcpy(b, "@SUM(1,\"2\")\r\n");      csvSafe(b, sizeof b); assert(!strcmp(b, "'@SUM(1  2 )??"));
  strcpy(b, "\x1b]0;x\x07" "AP\x7f");     csvSafe(b, sizeof b); assert(!strcmp(b, "?]0;x?AP?"));   // terminal escapes
  strcpy(b, "caf\xc3\xa9");              csvSafe(b, sizeof b); assert(!strcmp(b, "caf??"));        // non-ASCII, incl. UTF-8 C1 controls
  strcpy(b, "-Guest");                 csvSafe(b, sizeof b); assert(!strcmp(b, "'-Guest"));
  strcpy(b, "+1234567890123456789012"); csvSafe(b, sizeof b); assert(!strcmp(b, "'+123456789012345678901"));   // full buffer: last char drops
  strcpy(b, "Flock-2f3a");             csvSafe(b, sizeof b); assert(!strcmp(b, "Flock-2f3a"));
  strcpy(b, "");                       csvSafe(b, sizeof b); assert(!strcmp(b, ""));
  puts("ok");
  return 0;
}
