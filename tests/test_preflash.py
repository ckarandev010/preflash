"""Fixture projects are written at test time. Fake secrets are assembled from pieces so the
repository itself never contains a string that looks like a real key."""
import json
import textwrap

import pytest

from preflash.cli import main, scan
from preflash.sdkconfig import parse

FAKE_KEY_HEADER = "-----BEGIN " + "PRIVATE KEY-----"
FAKE_AWS = "AKIA" + "IOSFODNN7" + "EXAMPLE"   # AWS's documented example key ID

INSECURE_SDKCONFIG = """\
CONFIG_IDF_TARGET="esp32s3"
CONFIG_ESP_TLS_INSECURE=y
CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y
CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP=y
# CONFIG_SECURE_BOOT is not set
# CONFIG_SECURE_FLASH_ENC_ENABLED is not set
# CONFIG_NVS_ENCRYPTION is not set
CONFIG_BT_NIMBLE_ENABLED=y
CONFIG_BT_NIMBLE_SM_LEGACY=y
CONFIG_BT_NIMBLE_SM_SC=y
CONFIG_BT_NIMBLE_SM_SC_DEBUG_KEYS=y
CONFIG_LOG_DEFAULT_LEVEL_DEBUG=y
CONFIG_FREERTOS_CHECK_STACKOVERFLOW_NONE=y
# CONFIG_ESP_TASK_WDT_EN is not set
# CONFIG_MBEDTLS_CERTIFICATE_BUNDLE is not set
CONFIG_PARTITION_TABLE_TWO_OTA=y
# CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE is not set
CONFIG_EXAMPLE_WIFI_PASSWORD="hunter2hunter2"
"""

INSECURE_C = f"""\
#include "esp_wifi.h"
#define API_TOKEN "tok_1234567890abcdef"
static const char *KEY_ID = "{FAKE_AWS}";
void start(void) {{
    wifi_config_t sta = {{ .sta = {{ .ssid = "office", .password = "supersecret123" }} }};
    wifi_config_t ap = {{ .ap = {{ .ssid = "setup", .authmode = WIFI_AUTH_OPEN }} }};
    esp_mqtt_client_config_t m = {{ .broker.address.uri = "mqtt://broker.local" }};
    esp_http_client_config_t h = {{ .url = "https://up.example.com/fw.bin", .skip_cert_common_name_check = true }};
    esp_https_ota_config_t o = {{ .http_config = &h }};
    esp_https_ota(&o);
    ble_hs_cfg.sm_sc = 0;
    char buf[8]; strcpy(buf, "far too long for this");
    esp_log_level_set("*", ESP_LOG_VERBOSE);
}}
"""

HARDENED_SDKCONFIG = """\
CONFIG_IDF_TARGET="esp32s3"
# CONFIG_ESP_TLS_INSECURE is not set
# CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP is not set
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
# CONFIG_SECURE_BOOT_INSECURE is not set
CONFIG_SECURE_FLASH_ENC_ENABLED=y
# CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT is not set
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y
CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE=y
CONFIG_NVS_ENCRYPTION=y
CONFIG_BT_NIMBLE_ENABLED=y
# CONFIG_BT_NIMBLE_SM_LEGACY is not set
CONFIG_BT_NIMBLE_SM_SC=y
# CONFIG_BT_NIMBLE_SM_SC_DEBUG_KEYS is not set
CONFIG_LOG_DEFAULT_LEVEL_INFO=y
CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY=y
CONFIG_ESP_TASK_WDT_EN=y
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y
CONFIG_PARTITION_TABLE_TWO_OTA=y
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y
"""

HARDENED_C = """\
#include "esp_crt_bundle.h"
void start(void) {
    esp_mqtt_client_config_t m = { .broker.address.uri = "mqtts://broker.example.com" };
    esp_http_client_config_t h = { .url = "https://up.example.com/fw.bin", .crt_bundle_attach = esp_crt_bundle_attach };
    esp_https_ota_config_t o = { .http_config = &h };
    esp_https_ota(&o);
    char buf[32]; snprintf(buf, sizeof buf, "%s", "ok");
    // a comment mentioning strcpy( and mqtt:// is not code
}
"""


def make(tmp_path, name, sdkconfig, files, cfg_name="sdkconfig"):
    root = tmp_path / name
    (root / "main").mkdir(parents=True)
    (root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
    if sdkconfig is not None:
        (root / cfg_name).write_text(sdkconfig)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


@pytest.fixture
def insecure(tmp_path):
    return make(tmp_path, "insecure", INSECURE_SDKCONFIG, {
        "main/app.c": INSECURE_C,
        "certs/device.key": FAKE_KEY_HEADER + "\nMIIB...\n",
        "build/ignored.c": 'void x(void){ strcpy(a, b); }\n',
    })


@pytest.fixture
def hardened(tmp_path):
    return make(tmp_path, "hardened", HARDENED_SDKCONFIG, {"main/app.c": HARDENED_C})


def rules(findings):
    return {f.rule for f in findings}


def test_insecure_project_trips_every_rule(insecure):
    found, meta = scan(insecure)
    expected = {"PF001", "PF003", "PF004", "PF005", "PF010", "PF011", "PF012", "PF013", "PF015", "PF016",
                "PF017", "PF018", "PF019", "PF101", "PF102", "PF103", "PF104", "PF105", "PF106", "PF107",
                "PF108", "PF109", "PF110", "PF111"}
    assert expected <= rules(found), expected - rules(found)
    assert meta["config"] == "sdkconfig" and not meta["partial"]


def test_skip_cert_reports_pf001_not_pf002(insecure):
    found, _ = scan(insecure)
    assert "PF001" in rules(found) and "PF002" not in rules(found)


def test_hardened_project_is_clean(hardened):
    found, _ = scan(hardened)
    assert found == [], [(f.rule, f.evidence) for f in found]


def test_build_dir_is_skipped(insecure):
    found, _ = scan(insecure)
    assert not any(f.file.startswith("build") for f in found)


def test_secrets_are_masked_in_output(insecure):
    found, _ = scan(insecure)
    text = " ".join(f.evidence for f in found)
    assert "supersecret123" not in text and "hunter2hunter2" not in text and "tok_1234567890abcdef" not in text


def test_dev_profile_downgrades_lockdown_rules(insecure):
    found, _ = scan(insecure, profile="dev")
    by = {f.rule: f.severity for f in found}
    assert by["PF004"] == "info" and by["PF005"] == "info" and by["PF010"] == "info"
    assert by["PF001"] == "critical" and by["PF011"] == "critical"   # real mistakes stay loud


def test_dev_mode_flash_encryption_and_jtag(tmp_path):
    cfg = HARDENED_SDKCONFIG.replace("# CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT is not set", "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y") \
        .replace("CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y\n", "") + "CONFIG_SECURE_BOOT_ALLOW_JTAG=y\n"
    found, _ = scan(make(tmp_path, "p", cfg, {}))
    assert {"PF006", "PF007"} <= rules(found)


def test_download_mode_left_open(tmp_path):
    cfg = HARDENED_SDKCONFIG.replace("CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE=y\n", "CONFIG_SECURE_INSECURE_ALLOW_DL_MODE=y\n")
    found, _ = scan(make(tmp_path, "p", cfg, {}))
    assert "PF009" in rules(found)


def test_anti_rollback_missing_with_secure_boot(tmp_path):
    cfg = HARDENED_SDKCONFIG.replace("CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y", "# CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK is not set")
    found, _ = scan(make(tmp_path, "p", cfg, {}))
    assert rules(found) == {"PF014"}


def test_rollback_rule_needs_ota_partitions(tmp_path):
    cfg = INSECURE_SDKCONFIG.replace("CONFIG_PARTITION_TABLE_TWO_OTA=y", "CONFIG_PARTITION_TABLE_SINGLE_APP=y")
    assert "PF013" not in rules(scan(make(tmp_path, "single", cfg, {}))[0])
    custom = cfg + 'CONFIG_PARTITION_TABLE_CUSTOM=y\nCONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"\n'
    p = make(tmp_path, "custom", custom, {"partitions.csv": "nvs, data, nvs, , 0x6000\nota_0, app, ota_0, , 1M\nota_1, app, ota_1, , 1M\n"})
    assert "PF013" in rules(scan(p)[0])


def test_defaults_only_project_uses_kconfig_defaults(tmp_path):
    p = make(tmp_path, "d", "CONFIG_BT_NIMBLE_ENABLED=y\nCONFIG_ESP_TLS_INSECURE=y\n", {}, cfg_name="sdkconfig.defaults")
    found, meta = scan(p)
    assert meta["partial"] and meta["config"] == "sdkconfig.defaults"
    r = rules(found)
    assert {"PF002", "PF004", "PF005", "PF012"} <= r
    assert "PF017" not in r and "PF019" not in r   # watchdog and CA bundle default to on


def test_options_missing_for_the_chip_are_not_flagged(tmp_path):
    # a full sdkconfig that never mentions NVS_ENCRYPTION (not visible for this target) must not raise PF010
    found, _ = scan(make(tmp_path, "p", "CONFIG_IDF_TARGET=\"esp32\"\n# CONFIG_SECURE_BOOT is not set\n", {}))
    assert "PF010" not in rules(found) and "PF004" in rules(found)


def test_inline_ignore_comment(tmp_path):
    p = make(tmp_path, "p", None, {"main/a.c": 'void f(void){ strcpy(a, b); } // preflash: ignore PF108\n'})
    assert scan(p)[0] == []


def test_cli_ignore_flag_and_exit_codes(insecure, hardened, capsys):
    assert main([str(hardened)]) == 0
    assert main([str(insecure)]) == 1
    assert main([str(insecure), "--fail-on", "never"]) == 0
    assert main([str(insecure), "--ignore", ",".join(f"PF0{i:02d}" for i in range(1, 20)) + ",PF101,PF102,PF103,PF104,PF106,PF110,PF111", "--fail-on", "high"]) == 0
    assert main([str(insecure.parent / "nope")]) == 2
    capsys.readouterr()


def test_json_and_html_reports(insecure, tmp_path, capsys):
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    main([str(insecure), "--json", str(j), "--html", str(h), "--fail-on", "never"])
    data = json.loads(j.read_text())
    assert data["summary"]["critical"] >= 3 and data["findings"][0]["severity"] == "critical"
    f = next(x for x in data["findings"] if x["rule"] == "PF001")
    assert "5.5 Communicate securely" in f["standards"]["etsi_en_303_645"]
    page = h.read_text()
    assert "preflash report" in page and "supersecret123" not in page
    capsys.readouterr()


def test_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    out = capsys.readouterr().out
    assert "PF001" in out and "PF111" in out


def test_parse_handles_strings_and_unset(tmp_path):
    p = tmp_path / "sdkconfig"
    p.write_text(textwrap.dedent('''\
        CONFIG_A=y
        # CONFIG_B is not set
        CONFIG_C="hello world"
        CONFIG_D=0x1000
        '''))
    c = parse(p)
    assert c.on("A") and c.off("B") and c.get("C") == '"hello world"' and c.get("D") == "0x1000" and c.line("C") == 3
