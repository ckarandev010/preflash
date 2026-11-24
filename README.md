# preflash

**Find what your ESP32 firmware left unlocked before you ship it.**

AI assistants and copied examples make an ESP32 prototype work in an afternoon. To get there they
often switch security off: skip certificate checks, allow updates over plain HTTP, disable BLE
Secure Connections, hard-code the Wi-Fi password. The prototype works, and then it ships like that.

preflash reads an ESP-IDF project (its `sdkconfig` and source) and tells you, before you flash. Real output on
ESP-IDF's own NimBLE peripheral example:

```
$ preflash esp-idf/examples/bluetooth/nimble/bleprph
preflash 0.1.0  |  esp-idf/examples/bluetooth/nimble/bleprph  |  config: sdkconfig.defaults  |  profile: release
  note: only sdkconfig.defaults found; unset options were evaluated at their Kconfig defaults. Build the project for exact results.

[HIGH    ] PF004  Secure boot is off
           sdkconfig.defaults
           CONFIG_SECURE_BOOT not in sdkconfig.defaults; Kconfig default is off
           fix: Enable CONFIG_SECURE_BOOT (V2) for production builds. Read Espressif's secure boot guide first: it burns eFuses.

[HIGH    ] PF005  Flash encryption is off
           ...

[MEDIUM  ] PF107  BLE Secure Connections turned off in code
           main/main.c:596
           ble_hs_cfg.sm_sc = 0;
           fix: Set ble_hs_cfg.sm_sc = 1.

[MEDIUM  ] PF010  NVS is not encrypted
           ...

[LOW     ] PF012  BLE legacy pairing is still allowed
           ...

critical: 0  high: 2  medium: 2  low: 1  info: 0
```

Every finding has the exact line, why it matters, the fix, and which provision of **ETSI EN 303 645**,
which **OWASP IoT Top 10** item and which **NISTIR 8259A** capability it relates to. Secrets are masked
in all output.

## Install

```
pip install git+https://github.com/ckarandev010/preflash
```

Python 3.10+, no other dependencies.

## Use

```
preflash [project]              # scan; exit 1 if anything is high or critical
preflash . --profile dev        # chip lockdown settings (secure boot, flash encryption...) become info
preflash . --fail-on medium     # stricter gate for CI
preflash . --ignore PF012,PF108 # skip rules
preflash . --json r.json --html r.html
preflash --list-rules
```

Silence one line in source with a comment: `strcpy(buf, src); // preflash: ignore PF108`.

**Profiles.** Secure boot, release-mode flash encryption and a locked download mode burn eFuses, so nobody
turns them on while developing. `--profile dev` reports those as info and still fails on real mistakes
(skipped certificate checks, debug BLE keys, hard-coded secrets). Use the default `release` profile on
the build you ship.

**Generated vs defaults.** preflash prefers the generated `sdkconfig`. If only `sdkconfig.defaults` exists,
unset options are evaluated at their Kconfig defaults and the report says so. Build once
(`idf.py reconfigure`) for exact results.

### In CI

```yaml
- run: pip install git+https://github.com/ckarandev010/preflash
- run: preflash . --fail-on high --html preflash-report.html
```

## Rules

| ID | Severity | What |
|---|---|---|
| PF001 | critical | TLS server certificates not verified by default (`ESP_TLS_SKIP_SERVER_CERT_VERIFY`) |
| PF002 | medium | Insecure TLS options unlocked (`ESP_TLS_INSECURE`) |
| PF003 | high | Firmware updates allowed over plain HTTP (`ESP_HTTPS_OTA_ALLOW_HTTP`) |
| PF004 | high* | Secure boot off |
| PF005 | high* | Flash encryption off |
| PF006 | high* | Flash encryption in development mode |
| PF007 | high* | JTAG left enabled with secure boot / flash encryption |
| PF008 | medium* | Secure boot's insecure options unlocked |
| PF009 | medium* | UART download mode left fully open |
| PF010 | medium* | NVS not encrypted |
| PF011 | critical | BLE pairing uses the published debug key pair (`BT_NIMBLE_SM_SC_DEBUG_KEYS`) |
| PF012 | low | BLE legacy pairing still allowed |
| PF013 | medium | OTA partitions but no app rollback |
| PF014 | low* | Secure boot without anti-rollback |
| PF015 | low* | Debug / verbose default log level |
| PF016 | low | Stack overflow checking off |
| PF017 | low | Task watchdog off |
| PF018 | high | Password, token or key in the build config |
| PF019 | info | No CA certificate bundle |
| PF101 | high | Wi-Fi password hard-coded in source |
| PF102 | high | Secret in a `#define` |
| PF103 | critical | Private key in the project |
| PF104 | high | TLS hostname check turned off (`skip_cert_common_name_check`) |
| PF105 | medium | `mqtt://` or `ws://` (unencrypted) |
| PF106 | high | Open Wi-Fi access point (`WIFI_AUTH_OPEN`) |
| PF107 | medium | BLE Secure Connections turned off in code (`ble_hs_cfg.sm_sc = 0`) |
| PF108 | low | `strcpy` / `strcat` / `sprintf` / `gets` |
| PF109 | low | All logs forced to debug/verbose at runtime |
| PF110 | high | HTTPS OTA without a CA (`cert_pem`, `crt_bundle_attach` or global CA store) |
| PF111 | high | AWS access key ID in source |

\* info under `--profile dev`.

Every `CONFIG_` name above was checked against the Kconfig files of ESP-IDF v5.5. Options a chip
doesn't have (they don't appear in its generated `sdkconfig`) are never flagged.

## What it found in ESP-IDF's own examples

Run across the 453 example projects in ESP-IDF v5.5.5, the source rules found exactly the patterns
people copy into products:

- `ble_hs_cfg.sm_sc = 0` (Secure Connections off) in 10 NimBLE examples
- `skip_cert_common_name_check = true` in 6 OTA/MQTT examples (behind a Kconfig option)
- `WIFI_AUTH_OPEN` as the access point's fallback in 8 Wi-Fi examples
- private keys checked into 10 examples
- one example with `CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y`

That's fine for examples, and exactly why a check is needed before the copy ships.

## Limits

- Static checks of configuration and source text. Not a penetration test, not a certification, and it
  can't see what eFuses are actually burned on a chip (use `espefuse.py summary` for that).
- Source rules are line-based patterns, so they can miss code split across lines and can flag code that
  is never compiled. Use `// preflash: ignore` with a reason.
- ESP-IDF only for now.

## Develop

```
pip install -e .[dev]
pytest -q
```

Test fixtures are generated at test time; fake secrets are assembled from pieces so this repository
never contains anything that looks like a real key.

MIT licence. Not affiliated with Espressif, ETSI or OWASP.
