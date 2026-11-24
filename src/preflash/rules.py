"""Checks. Config rules read sdkconfig; source rules scan C/C++ files line by line.

Every option name used here exists in ESP-IDF v5.5 Kconfig. Rules marked lockdown=True are normal while
developing (you can't keep re-flashing a chip with secure boot and release-mode flash encryption), so the
"dev" profile reports them as info instead of failing the build.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

from .standards import expand

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    file: str
    line: int | None
    evidence: str
    why: str
    fix: str
    standards: dict = field(default_factory=dict)


@dataclass
class Rule:
    id: str
    severity: str
    title: str
    why: str
    fix: str
    std: dict
    lockdown: bool = False


def R(id, severity, title, why, fix, en=(), owasp=(), nist=(), lockdown=False):
    return Rule(id, severity, title, why, fix, expand(en, owasp, nist), lockdown)


# ---------------------------------------------------------------- config rules
CONFIG_RULES = {
    "PF001": R("PF001", "critical", "TLS server certificates are not verified by default",
               "CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY makes every TLS connection that doesn't set its own CA accept any server, "
               "so anyone on the network path can impersonate your cloud, MQTT broker or update server.",
               "Turn it off and give each connection a CA: crt_bundle_attach = esp_crt_bundle_attach, or cert_pem.",
               en=("5.5",), owasp=("I7",), nist=("DATA",)),
    "PF002": R("PF002", "medium", "Insecure TLS options are unlocked",
               "CONFIG_ESP_TLS_INSECURE exists only to allow test-only TLS shortcuts. In a shipping build it is a sign one is in use.",
               "Turn off CONFIG_ESP_TLS_INSECURE.", en=("5.5",), owasp=("I9",), nist=("CFG",)),
    "PF003": R("PF003", "high", "Firmware updates are allowed over plain HTTP",
               "CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP lets the device download an update without encryption or server identity, "
               "so a network attacker can push their own firmware.",
               "Turn it off and serve updates over HTTPS with certificate verification.",
               en=("5.3", "5.5"), owasp=("I4",), nist=("UPDATE",)),
    "PF004": R("PF004", "high", "Secure boot is off",
               "Without secure boot the chip runs any firmware written to flash, including an attacker's.",
               "Enable CONFIG_SECURE_BOOT (V2) for production builds. Read Espressif's secure boot guide first: it burns eFuses.",
               en=("5.7",), owasp=("I10", "I4"), nist=("UPDATE",), lockdown=True),
    "PF005": R("PF005", "high", "Flash encryption is off",
               "Anyone with the board can read the flash and get the firmware, Wi-Fi credentials, keys and certificates.",
               "Enable CONFIG_SECURE_FLASH_ENC_ENABLED in release mode for production. It burns eFuses; read the guide first.",
               en=("5.4",), owasp=("I10", "I7"), nist=("DATA",), lockdown=True),
    "PF006": R("PF006", "high", "Flash encryption is in development mode",
               "Development mode keeps plaintext re-flashing possible over serial, which defeats the encryption on a shipped device.",
               "Use CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE for production builds.",
               en=("5.4",), owasp=("I10",), nist=("DATA",), lockdown=True),
    "PF007": R("PF007", "high", "JTAG stays enabled with secure boot / flash encryption",
               "CONFIG_SECURE_BOOT_ALLOW_JTAG keeps the debug port open. ESP-IDF's own help says this negates all protections of flash encryption.",
               "Turn it off for production builds.", en=("5.6",), owasp=("I10",), nist=("ACCESS",), lockdown=True),
    "PF008": R("PF008", "medium", "Secure boot's insecure options are unlocked",
               "CONFIG_SECURE_BOOT_INSECURE disables some of secure boot's default protections.",
               "Turn it off unless you know exactly which protection you need to relax and why.",
               en=("5.7",), owasp=("I9",), nist=("CFG",), lockdown=True),
    "PF009": R("PF009", "medium", "UART download mode is left fully open",
               "With secure boot or flash encryption on, the ROM download mode is still the easiest way into the chip.",
               "Choose CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE (secure download mode) or CONFIG_SECURE_DISABLE_ROM_DL_MODE.",
               en=("5.6",), owasp=("I10",), nist=("ACCESS",), lockdown=True),
    "PF010": R("PF010", "medium", "NVS is not encrypted",
               "Wi-Fi passwords, tokens and keys saved in NVS sit in flash as plain text.",
               "Enable CONFIG_NVS_ENCRYPTION (needs flash encryption or an HMAC eFuse key).",
               en=("5.4",), owasp=("I7",), nist=("DATA",), lockdown=True),
    "PF011": R("PF011", "critical", "BLE pairing uses the published debug key pair",
               "CONFIG_BT_NIMBLE_SM_SC_DEBUG_KEYS uses the Bluetooth spec's well-known debug keys, so anyone listening can decrypt pairing and traffic.",
               "Turn it off.", en=("5.5",), owasp=("I7",), nist=("DATA",)),
    "PF012": R("PF012", "low", "BLE legacy pairing is still allowed",
               "Legacy pairing can be downgraded to and cracked from a captured pairing exchange.",
               "If every phone you support has Bluetooth 4.2+, turn off CONFIG_BT_NIMBLE_SM_LEGACY and require Secure Connections.",
               en=("5.5",), owasp=("I7",), nist=("DATA",)),
    "PF013": R("PF013", "medium", "A bad update can't roll back",
               "Without app rollback, an update that boots but doesn't work leaves the device stuck until someone visits it.",
               "Enable CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE and call esp_ota_mark_app_valid_cancel_rollback() once the new app is healthy.",
               en=("5.3", "5.9"), owasp=("I4",), nist=("UPDATE",)),
    "PF014": R("PF014", "low", "Old signed firmware can be re-installed",
               "With secure boot on but no anti-rollback, an attacker can install an older, signed but vulnerable version.",
               "Enable CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK and bump the security version when you fix a vulnerability.",
               en=("5.3",), owasp=("I4",), nist=("UPDATE",), lockdown=True),
    "PF015": R("PF015", "low", "Debug-level logging in the build",
               "Debug and verbose logs often print keys, tokens, URLs and internal state to the serial port.",
               "Use Info or Warning as the default log level for production builds.",
               en=("5.6", "5.8"), owasp=("I9",), nist=("STATE",), lockdown=True),
    "PF016": R("PF016", "low", "Stack overflow checking is off",
               "A stack overflow then corrupts memory silently instead of stopping the task.",
               "Choose a FreeRTOS stack overflow check method (CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY).",
               en=("5.9", "5.13"), owasp=("I5",), nist=("STATE",)),
    "PF017": R("PF017", "low", "Task watchdog is off",
               "A hung task stays hung; nothing restarts the device.",
               "Enable CONFIG_ESP_TASK_WDT_EN.", en=("5.9",), nist=("STATE",)),
    "PF018": R("PF018", "high", "Secret stored in the build config",
               "A password or key in sdkconfig ends up in the firmware image, in the build folder and often in git.",
               "Provision secrets per device at setup (BLE/SoftAP provisioning, encrypted NVS) instead of compiling them in.",
               en=("5.1", "5.4"), owasp=("I1",), nist=("DATA",)),
    "PF019": R("PF019", "info", "No CA certificate bundle",
               "Without the bundle every TLS connection needs its own certificate, and it is tempting to skip verification instead.",
               "Keep CONFIG_MBEDTLS_CERTIFICATE_BUNDLE on, or make sure every connection pins a cert_pem.",
               en=("5.5",), owasp=("I7",), nist=("DATA",)),
}

_SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|_PASS$|_PSK$|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)")


def check_config(cfg, profile="release", project=None):
    out = []

    def hit(rid, name, evidence=None):
        r = CONFIG_RULES[rid]
        sev = "info" if (profile == "dev" and r.lockdown) else r.severity
        if evidence:
            ev = evidence
        elif name not in cfg.values:
            ev = f"CONFIG_{name} not in {cfg.path.name}; Kconfig default is {'on' if cfg.get(name) == 'y' else 'off'}"
        else:
            ev = f"CONFIG_{name}={cfg.get(name)}" if cfg.get(name) != "n" else f"# CONFIG_{name} is not set"
        out.append(Finding(r.id, sev, r.title, str(cfg.path), cfg.line(name), ev, r.why, r.fix, r.std))

    if cfg.on("ESP_TLS_SKIP_SERVER_CERT_VERIFY"): hit("PF001", "ESP_TLS_SKIP_SERVER_CERT_VERIFY")
    if cfg.on("ESP_TLS_INSECURE") and not cfg.on("ESP_TLS_SKIP_SERVER_CERT_VERIFY"): hit("PF002", "ESP_TLS_INSECURE")
    if cfg.on("ESP_HTTPS_OTA_ALLOW_HTTP"): hit("PF003", "ESP_HTTPS_OTA_ALLOW_HTTP")
    secure_boot, flash_enc = cfg.on("SECURE_BOOT"), cfg.on("SECURE_FLASH_ENC_ENABLED")
    if cfg.off("SECURE_BOOT"): hit("PF004", "SECURE_BOOT")
    if cfg.off("SECURE_FLASH_ENC_ENABLED"): hit("PF005", "SECURE_FLASH_ENC_ENABLED")
    if flash_enc and cfg.on("SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT"): hit("PF006", "SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT")
    if cfg.on("SECURE_BOOT_ALLOW_JTAG"): hit("PF007", "SECURE_BOOT_ALLOW_JTAG")
    if cfg.on("SECURE_BOOT_INSECURE"): hit("PF008", "SECURE_BOOT_INSECURE")
    if (secure_boot or flash_enc) and not (cfg.on("SECURE_ENABLE_SECURE_ROM_DL_MODE") or cfg.on("SECURE_DISABLE_ROM_DL_MODE")):
        name = "SECURE_INSECURE_ALLOW_DL_MODE" if cfg.known("SECURE_INSECURE_ALLOW_DL_MODE") else "SECURE_BOOT"
        hit("PF009", name, "neither CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE nor CONFIG_SECURE_DISABLE_ROM_DL_MODE is set")
    if cfg.off("NVS_ENCRYPTION"): hit("PF010", "NVS_ENCRYPTION")
    if cfg.on("BT_NIMBLE_SM_SC_DEBUG_KEYS"): hit("PF011", "BT_NIMBLE_SM_SC_DEBUG_KEYS")
    if cfg.on("BT_NIMBLE_ENABLED") and cfg.on("BT_NIMBLE_SM_LEGACY") and cfg.on("BT_NIMBLE_SM_SC"):
        hit("PF012", "BT_NIMBLE_SM_LEGACY")
    if cfg.off("BOOTLOADER_APP_ROLLBACK_ENABLE") and _uses_ota(cfg, project):
        hit("PF013", "BOOTLOADER_APP_ROLLBACK_ENABLE")
    if secure_boot and cfg.on("BOOTLOADER_APP_ROLLBACK_ENABLE") and cfg.off("BOOTLOADER_APP_ANTI_ROLLBACK"):
        hit("PF014", "BOOTLOADER_APP_ANTI_ROLLBACK")
    for lvl in ("LOG_DEFAULT_LEVEL_DEBUG", "LOG_DEFAULT_LEVEL_VERBOSE"):
        if cfg.on(lvl): hit("PF015", lvl)
    if cfg.on("FREERTOS_CHECK_STACKOVERFLOW_NONE"): hit("PF016", "FREERTOS_CHECK_STACKOVERFLOW_NONE")
    if cfg.off("ESP_TASK_WDT_EN"): hit("PF017", "ESP_TASK_WDT_EN")
    if cfg.off("MBEDTLS_CERTIFICATE_BUNDLE"): hit("PF019", "MBEDTLS_CERTIFICATE_BUNDLE")
    for name, val in cfg.values.items():
        if _SECRET_NAME.search(name) and val.startswith('"') and len(val.strip('"')) > 0:
            masked = val.strip('"')
            masked = masked[:2] + "*" * max(3, len(masked) - 2)
            hit("PF018", name, f'CONFIG_{name}="{masked}"')
    return out


def _uses_ota(cfg, project):
    """True when the partition table has OTA slots (built-in two-OTA table or a custom CSV with ota_0)."""
    if cfg.on("PARTITION_TABLE_TWO_OTA"):
        return True
    name = (cfg.get("PARTITION_TABLE_CUSTOM_FILENAME") or "").strip('"')
    if project and name:
        p = Path(project) / name
        if p.is_file() and re.search(r"^\s*\w+\s*,\s*app\s*,\s*ota_0", p.read_text(errors="replace"), re.M):
            return True
    return False


# ---------------------------------------------------------------- source rules
SOURCE_EXT = {".c", ".h", ".cpp", ".cc", ".hpp", ".ino"}
SKIP_DIRS = {"build", "managed_components", ".git", "components_extra", "node_modules", ".pio"}
TEXT_EXT = SOURCE_EXT | {".pem", ".key", ".txt", ".json", ".cfg", ".csv", ".yml", ".yaml", ".py", ".ini", ".defaults"}

SRC = [
    # id, severity, regex, title, why, fix, en, owasp, nist
    ("PF101", "high", re.compile(r"\.password\s*=\s*\"([^\"]+)\""),
     "Wi-Fi password hard-coded in source",
     "Every device ships with the same password baked into the firmware, readable by anyone who dumps the flash.",
     "Provision Wi-Fi per device (esp_prov / BLE or SoftAP provisioning) and store it in encrypted NVS.",
     ("5.1", "5.4"), ("I1",), ("DATA",)),
    ("PF102", "high", re.compile(r"#\s*define\s+\w*(PASS|PASSWORD|PSK|SECRET|TOKEN|API_?KEY)\w*\s+\"([^\"]+)\"", re.I),
     "Secret hard-coded in a #define",
     "Compiled into every image and usually committed to git.",
     "Load secrets at provisioning time from encrypted NVS instead.",
     ("5.1", "5.4"), ("I1",), ("DATA",)),
    ("PF103", "critical", re.compile(r"-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----"),
     "Private key in the project",
     "A private key in the source tree is shared by every device and everyone with repo access.",
     "Generate a key per device at manufacture or first boot; keep it in the encrypted NVS or the chip's secure storage.",
     ("5.4",), ("I1", "I7"), ("DATA",)),
    ("PF104", "high", re.compile(r"\bskip_cert_common_name_check\s*=\s*(true|1)\b"),
     "TLS hostname check turned off",
     "The device accepts a valid certificate for ANY domain, so a cheap certificate for another site is enough to impersonate your server.",
     "Remove skip_cert_common_name_check, or set common_name to the server's real name.",
     ("5.5",), ("I7",), ("DATA",)),
    ("PF105", "medium", re.compile(r"\"(mqtt|ws)://"),
     "Unencrypted MQTT or WebSocket URI",
     "Credentials and data cross the network in plain text and can be changed in transit.",
     "Use mqtts:// or wss:// with server certificate verification.",
     ("5.5",), ("I7",), ("DATA",)),
    ("PF106", "high", re.compile(r"\.authmode\s*=\s*WIFI_AUTH_OPEN\b"),
     "Open Wi-Fi access point",
     "Anyone nearby can join the device's access point. Often written as a fallback for when no password is configured, which is exactly how devices ship open.",
     "Use WIFI_AUTH_WPA2_PSK or WPA3 with a per-device password (print it on the label).",
     ("5.1", "5.6"), ("I2",), ("ACCESS",)),
    ("PF107", "medium", re.compile(r"\bble_hs_cfg\.sm_sc\s*=\s*0\b"),
     "BLE Secure Connections turned off in code",
     "Pairing falls back to legacy pairing, which can be cracked from a captured exchange.",
     "Set ble_hs_cfg.sm_sc = 1.",
     ("5.5",), ("I7",), ("DATA",)),
    ("PF108", "low", re.compile(r"(?<![\w.])(strcpy|strcat|sprintf|vsprintf|gets)\s*\("),
     "Unbounded string function",
     "No length check: a long input overflows the buffer. A common source of memory-corruption bugs in AI-written C.",
     "Use strlcpy / strlcat / snprintf with the buffer size.",
     ("5.13",), ("I5",), ("STATE",)),
    ("PF109", "low", re.compile(r"esp_log_level_set\s*\(\s*\"\*\"\s*,\s*ESP_LOG_(VERBOSE|DEBUG)\s*\)"),
     "All logs forced to debug/verbose at runtime",
     "Debug output often prints secrets and internal state to the serial port.",
     "Remove it or guard it behind a debug build flag.",
     ("5.6", "5.8"), ("I9",), ("STATE",)),
    ("PF110", "high", re.compile(r"esp_https_ota(?:_begin)?\s*\("),
     "OTA update without server verification",
     "This file starts an HTTPS OTA but never sets a CA (cert_pem, crt_bundle_attach or the global CA store), so the update server's identity may not be checked.",
     "Set .crt_bundle_attach = esp_crt_bundle_attach or .cert_pem on the http client config used for OTA.",
     ("5.3", "5.5"), ("I4",), ("UPDATE",)),
    ("PF111", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "AWS access key ID in source",
     "Cloud credentials in firmware can be extracted from any device and used against your account.",
     "Use per-device X.509 certificates (e.g. AWS IoT) instead of account keys.",
     ("5.1", "5.4"), ("I1",), ("DATA",)),
]
SRC_RULES = {r[0]: r for r in SRC}
_IGNORE = re.compile(r"preflash:\s*ignore\s+([A-Z0-9_, ]+)", re.I)
_CA_SET = re.compile(r"\b(cert_pem|crt_bundle_attach|use_global_ca_store)\b")


def _files(root):
    root = Path(root)
    for p in root.rglob("*"):
        if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            yield p


def check_sources(root):
    out = []
    root = Path(root)
    if root.is_file():
        return out
    for p in _files(root):
        ext = p.suffix.lower()
        if ext not in TEXT_EXT and p.name not in ("sdkconfig", "sdkconfig.defaults"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        lines = text.splitlines()
        is_src = ext in SOURCE_EXT
        has_ca = bool(_CA_SET.search(text))
        for no, line in enumerate(lines, 1):
            ign = _IGNORE.search(line)
            ignored = {x.strip().upper() for x in ign.group(1).replace(",", " ").split()} if ign else set()
            stripped = line.strip()
            if is_src and (stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")):
                continue
            for rid, sev, rx, title, why, fix, en, ow, ni in SRC:
                if rid in ignored:
                    continue
                if rid != "PF103" and not is_src:
                    continue
                m = rx.search(line)
                if not m:
                    continue
                if rid == "PF110" and has_ca:
                    continue
                if rid == "PF101" and m.group(1).startswith("CONFIG_"):
                    continue
                ev = stripped
                if rid in ("PF101", "PF102"):
                    secret = m.group(m.lastindex)
                    ev = stripped.replace(secret, secret[:2] + "*" * max(3, len(secret) - 2))
                if rid == "PF103":
                    ev = "-----BEGIN ... PRIVATE KEY-----"
                out.append(Finding(rid, sev, title, rel, no, ev[:160], why, fix, expand(en, ow, ni)))
                if rid == "PF110":
                    break
    return out
