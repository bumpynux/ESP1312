# Law enforcement and surveillance gear: RF fingerprints

Based on my research, this is what US police gear and surveillance tech looks like over WiFi and Bluetooth LE, and which of it ESP1312 can match today.

## How anything gets identified

A device shows up over the air in four ways. ESP1312 sees all four, with the limits in the last column.

| Channel            | What's in it                                                               | ESP1312 today                                            |
|--------------------|----------------------------------------------------------------------------|----------------------------------------------------------|
| BLE advertisement  | MAC (often randomized), company ID, 16-bit service UUIDs, sometimes a name | yes                                                      |
| WiFi beacon        | BSSID (real MAC), SSID, channel, encryption                                | yes                                                      |
| BLE scan response  | extra name and UUIDs, only if we send a scan request                       | yes, in probe mode                                       |
| WiFi probe request | a client asking for its network, sent even with no AP                      | yes, promiscuous mode riding on the scan, real MACs only |

Some things never show up here, like Bluetooth Classic (radios, speaker mics, most printers), cellular (cell-site simulators, LTE uplinks), and wired cameras.

Status key: **IN** already in `signatures.h`. **ADD** verified identifier, not added yet. **CAPTURE** exists, but the identifier has to come from a real recording near the hardware. **GAP** identifiable but needs a capability the logger doesn't have. **NO** not visible over WiFi or BLE.

## Officer-worn

| Gear                    | Examples                                                                   | Emits                                                 | Identifying feature                                                                                                                                                                         | Status                        |
|-------------------------|----------------------------------------------------------------------------|-------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
| Body camera             | Axon Body 3, Body 4                                                        | BLE always, WiFi when uploading                       | company ID `034d` (TASER International), service UUID `fc81`, OUI `00:25:df`. Some units seen in the field advertise only a 128-bit UUID spelling `AXJANUSBWCDEVICE`, which is in the table | IN                            |
| Holster sensor          | Axon Signal Sidearm                                                        | BLE burst for 30 s when the gun is drawn, 30 ft range | Axon company ID. Reported as a 20 to 50 packets/s burst versus 1/s idle                                                                                                                     | IN (ID), CAPTURE (burst rate) |
| Conducted energy weapon | Taser 7, Taser 10                                                          | BLE via Signal Performance Power Magazine             | Axon company ID, reported not verified                                                                                                                                                      | IN                            |
| Body camera             | Motorola WatchGuard V300, V700                                             | WiFi for upload, Bluetooth to APX radios              | OUI `00:1d:96` (WatchGuard Video). Name pattern reported as `SI V…`                                                                                                                         | IN (OUI), CAPTURE (name)      |
| Body camera             | Digital Ally FirstVu                                                       | WiFi, BLE                                             | OUI `00:23:bd`. Name reported as `DA…` or `FirstVu…`                                                                                                                                        | IN (OUI), CAPTURE (name)      |
| Body camera             | Getac BC-03/04, Utility BodyWorn, Reveal, Panasonic i-PRO BWC4000, Wolfcom | WiFi, BLE                                             | no registered OUI or company ID found                                                                                                                                                       | CAPTURE                       |
| Portable radio          | Motorola APX NEXT, L3Harris XL-200P                                        | WiFi, Bluetooth, LTE                                  | no Bluetooth company ID found for Motorola Solutions. Speaker mics use Bluetooth Classic                                                                                                    | CAPTURE                       |
| Phone                   | any                                                                        | BLE with rotating MAC                                 | Apple `004c` or Google, same as everyone else                                                                                                                                               | NO                            |

## In vehicle

| Gear                 | Examples                                       | Emits                       | Identifying feature                                                                                                                                               | Status    |
|----------------------|------------------------------------------------|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| In-car video         | Axon Fleet 3 with Fleet Hub and Signal Vehicle | BLE to trigger body cams    | Axon company ID                                                                                                                                                   | IN        |
| In-car video         | WatchGuard 4RE                                 | WiFi                        | OUI `00:1d:96`                                                                                                                                                    | IN        |
| In-car video         | Digital Ally DVM-800                           | WiFi                        | OUI `00:23:bd`                                                                                                                                                    | IN        |
| In-car video         | Coban, Panasonic Arbitrator, Getac Zeus        | WiFi                        | nothing registered under a distinct name                                                                                                                          | CAPTURE   |
| Vehicle router       | Cradlepoint IBR900, R1900                      | WiFi AP, LTE                | OUIs `00:30:44`, `00:e0:1c`. Also in buses, ambulances, retail, and fixed sites (e.g., Tesla Superchargers use one for backhaul). One moving with you is the tell | IN (weak) |
| Vehicle router       | Sierra Wireless AirLink MP70, MG90, XR80       | WiFi AP, LTE                | Sierra OUIs sit in thousands of unrelated IoT products. SSID is the only hope                                                                                     | CAPTURE   |
| Mobile data terminal | Panasonic Toughbook, Getac, Dell Rugged        | WiFi client                 | laptop OUIs, nothing police-specific                                                                                                                              | NO        |
| E-citation printer   | Brother PocketJet 7/8, Zebra ZQ520/ZQ630       | Bluetooth Classic, some BLE | model-name advert (`PJ-8…`, `ZQ520…`) is plausible, unverified                                                                                                    | CAPTURE   |
| Radar, lidar         | Stalker DSR 2X, Kustom Signals, LTI TruSpeed   | mostly wired to the MDT     | no wireless identifier found                                                                                                                                      | NO        |
| Fleet telematics     | CalAmp, Geotab, Samsara                        | BLE beacons, WiFi           | shared with every civilian fleet                                                                                                                                  | NO        |

## Deployed surveillance

| Gear                 | Examples                            | Emits                                                                 | Identifying feature                                                                                                                                                                                                                                                                                                                        | Status                              |
|----------------------|-------------------------------------|-----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------|
| ALPR camera          | Flock Falcon, Sparrow               | WiFi client, BLE on battery units                                     | OUI `b4:1e:52` is registered to Flock. Provisioning AP `Flock-XXXX` is rare now. Battery and Raven advertise company ID `09c8` (Xuntong) with names `Flock`, `Penguin`, `Pigvision`, `FS Ext Battery`                                                                                                                                      | IN                                  |
| ALPR camera          | Flock Falcon, main behavior         | WiFi probe requests, reported every ~125 ms in STA mode, no AP needed | a live tell when it lands. Probes are logged as `PROBE` rows, but only tagged Flock when the probe carries Flock's own `b4:1e:52` OUI. Falcons often probe from a WiFi-module MAC instead (Liteon `e4:aa:ea` and 30 others), and those prefixes are left out because other products share them, so many Flock probes log unmatched for now | IN (capture), CAPTURE (module OUIs) |
| Gunshot sensor       | Flock Raven                         | BLE                                                                   | company ID `09c8`, service UUIDs `3100` to `3500` reported. `180a`, `1809`, `1819` also listed but those are generic                                                                                                                                                                                                                       | IN                                  |
| ALPR camera          | Motorola Vigilant L5Q, L6Q          | LTE, WiFi, Bluetooth (L6Q pairs to a phone app)                       | none published. One public list attributes `00:0e:58` to Motorola ALPR, but that prefix is Sonos                                                                                                                                                                                                                                           | CAPTURE                             |
| ALPR camera          | Genetec AutoVu SharpV, SharpZ3      | wired PoE, WiFi on some                                               | OUIs `00:bf:15`, `0c:bf:15`                                                                                                                                                                                                                                                                                                                | IN                                  |
| ALPR camera          | Leonardo ELSAG, Rekor, Axon Outpost | wired, LTE                                                            | nothing registered                                                                                                                                                                                                                                                                                                                         | CAPTURE                             |
| Gunshot sensor       | SoundThinking ShotSpotter           | cellular, wired                                                       | nothing on 2.4 GHz                                                                                                                                                                                                                                                                                                                         | NO                                  |
| Fixed camera         | Axis, Avigilon, Hikvision, Verkada  | wired                                                                 | OUIs exist but almost never on air                                                                                                                                                                                                                                                                                                         | NO                                  |
| Cell-site simulator  | Harris Stingray, Hailstorm          | cellular                                                              | needs LTE control-plane monitoring. EFF Rayhunter on an Orbic RC400L is the tool                                                                                                                                                                                                                                                           | NO                                  |
| Drone, any compliant | DJI, Skydio X10, BRINC Lemur, Autel | FAA Remote ID broadcast                                               | BLE service data UUID `fffa` (ASTM F3411 / Open Drone ID), logged as a `DRONE` hit. WiFi beacon form (vendor element OUI `fa:0b:bc`) is sniffed and logged as an `RID` row with the same UUID. WiFi NAN form not captured                                                                                                                  | IN (BLE, WiFi beacon), GAP (NAN)    |
| Drone controller     | DJI, Parrot, Skydio                 | WiFi AP                                                               | vendor OUIs                                                                                                                                                                                                                                                                                                                                | IN                                  |

## Home security, for context and false positives

| Gear                | Examples                                  | Identifying feature                    | Status         |
|---------------------|-------------------------------------------|----------------------------------------|----------------|
| Doorbells, cameras  | Ring, Blink, Nest, Arlo, Wyze, SimpliSafe | registered OUIs, all 24-bit blocks     | IN             |
| Doorbells, cameras  | Eufy                                      | nothing registered under Eufy or Anker | CAPTURE        |
| Hidden WiFi cameras | generic                                   | SSID words like `cam`, `ipcam`, `dvr`  | CAPTURE (weak) |

## Intrusive wearables and trackers

| Gear           | Examples                                          | Emits | Identifying feature                                                                                                                                      | Status  |
|----------------|---------------------------------------------------|-------|----------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| Camera glasses | Meta Ray-Ban, Oakley Meta                         | BLE   | company ID `0d53` (Luxottica) or `01ab` (Meta Platforms, seen in the field), service UUID `fd5f` (Oculus VR), names `Ray-Ban`, `Wayfarer`, `Oakley Meta` | IN      |
| Camera glasses | Snap Spectacles, Amazon Echo Frames, XREAL, Vuzix | BLE   | detected by commercial tools via name and UUID, not published                                                                                            | CAPTURE |
| AI recorders   | Humane Pin, Limitless pendant, Plaud NotePin, Bee | BLE   | same                                                                                                                                                     | CAPTURE |
| Tracker        | Apple AirTag, Find My accessories                 | BLE   | company ID `004c` with payload type `0x12`, from the `mfg_data` column.     Logged as `FINDMY`, no chirp                                                 | IN      |
| Tracker        | Tile                                              | BLE   | service UUID `feed` or `feec`, company ID `00c7`. Logged, no chirp                                                                                       | IN      |
| Tracker        | Samsung SmartTag                                  | BLE   | service UUID `fd5a`. Company ID `0075` is all of Samsung, so not used                                                                                    | IN      |
| Tracker        | Chipolo, Pebblebee                                | BLE   | name prefix only                                                                                                                                         | CAPTURE |

## Still open

1. **Remote ID over WiFi NAN.** Some drones send Remote ID in WiFi NAN action frames instead of beacons. The sniffer only keeps beacons and probe requests, so it would need to accept NAN frames (management subtype 13) and read the NAN service descriptor inside them.
2. **Axon Signal burst rate.** An Axon Signal advertises about once a second when idle and tens of times a second when a weapon is drawn. The logger records the device but not the rate, so it can't tell the two apart. Counting adverts per MAC per second would.

Everything marked CAPTURE grows from the ALL log. A device that keeps appearing near cruisers with a fixed company ID, UUID, or name becomes a row, with the capture as its source.

## Sources

Sources for the signature rows themselves are listed per row in [SIGNATURES.md](../SIGNATURES.md). The gear claims above also draw on:

- [Axon Signal Sidearm](https://www.axon.com/products/axon-signal)
- [Motorola V300 and APX radio integration](https://www.motorolasolutions.com/en_us/blog/v300-apx-radio-integration)
- Motorola L6Q datasheet, motorolasolutions.com
- [EFF Rayhunter](https://github.com/EFForg/rayhunter)
- [bleGuard device list](https://bleguard.com)
