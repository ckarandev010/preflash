"""Read an ESP-IDF sdkconfig (full) or sdkconfig.defaults (partial)."""
import re
from dataclasses import dataclass, field
from pathlib import Path

_SET = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(.*)$")
_UNSET = re.compile(r"^#\s*CONFIG_([A-Za-z0-9_]+) is not set\s*$")

# Kconfig defaults (ESP-IDF v5.x) for options the rules read, used when only sdkconfig.defaults exists.
KCONFIG_DEFAULTS = {
    "SECURE_BOOT": "n",
    "SECURE_FLASH_ENC_ENABLED": "n",
    "NVS_ENCRYPTION": "n",
    "BOOTLOADER_APP_ROLLBACK_ENABLE": "n",
    "BT_NIMBLE_SM_LEGACY": "y",
    "BT_NIMBLE_SM_SC": "y",
    "ESP_TASK_WDT_EN": "y",
    "MBEDTLS_CERTIFICATE_BUNDLE": "y",
    "ESP_TLS_INSECURE": "n",
    "ESP_TLS_SKIP_SERVER_CERT_VERIFY": "n",
    "ESP_HTTPS_OTA_ALLOW_HTTP": "n",
    "BT_NIMBLE_SM_SC_DEBUG_KEYS": "n",
}


@dataclass
class SdkConfig:
    path: Path
    values: dict = field(default_factory=dict)   # name -> raw value ("y", "n", '"str"', "123")
    lines: dict = field(default_factory=dict)    # name -> 1-based line number
    partial: bool = False                        # True when read from sdkconfig.defaults

    def known(self, name):
        return name in self.values or (self.partial and name in KCONFIG_DEFAULTS)

    def get(self, name, default=None):
        if name in self.values:
            return self.values[name]
        if self.partial and name in KCONFIG_DEFAULTS:
            return KCONFIG_DEFAULTS[name]
        return default

    def on(self, name):
        return self.get(name) == "y"

    def off(self, name):
        """True only when the option is visible for this chip and switched off."""
        return self.known(name) and self.get(name) != "y"

    def line(self, name):
        return self.lines.get(name)


def parse(path):
    path = Path(path)
    cfg = SdkConfig(path=path, partial=path.name != "sdkconfig")
    for no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        s = raw.strip()
        m = _SET.match(s)
        if m:
            cfg.values[m.group(1)] = m.group(2).strip()
            cfg.lines[m.group(1)] = no
            continue
        m = _UNSET.match(s)
        if m:
            cfg.values[m.group(1)] = "n"
            cfg.lines[m.group(1)] = no
    return cfg


def find(project):
    """Prefer the generated sdkconfig; fall back to sdkconfig.defaults."""
    project = Path(project)
    if project.is_file():
        return project
    for name in ("sdkconfig", "sdkconfig.defaults"):
        p = project / name
        if p.is_file():
            return p
    return None
