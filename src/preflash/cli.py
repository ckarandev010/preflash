"""preflash command line.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings at or above --fail-on, 2 = usage error.
"""
import argparse
import sys
from pathlib import Path

from . import __version__
from . import report
from .rules import CONFIG_RULES, RANK, SEVERITIES, SRC_RULES, check_config, check_sources
from .sdkconfig import find, parse


def scan(project, profile="release", ignore=()):
    project = Path(project)
    cfg_path = find(project)
    findings, partial = [], False
    root = project if project.is_dir() else project.parent
    if cfg_path:
        cfg = parse(cfg_path)
        partial = cfg.partial
        findings += check_config(cfg, profile, root)
        for f in findings:
            try:
                f.file = Path(f.file).relative_to(root).as_posix()
            except ValueError:
                pass
    if project.is_dir():
        findings += check_sources(project)
    ignore = {i.upper() for i in ignore}
    findings = [f for f in findings if f.rule not in ignore]
    meta = {"project": str(project), "config": str(cfg_path.relative_to(root)) if cfg_path else None, "profile": profile, "partial": partial}
    return findings, meta


def list_rules():
    lines = []
    for r in CONFIG_RULES.values():
        lines.append(f"{r.id}  {r.severity:8}  {r.title}{'  (info in dev profile)' if r.lockdown else ''}")
    for rid, sev, _rx, title, *_ in SRC_RULES.values():
        lines.append(f"{rid}  {sev:8}  {title}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="preflash", description="Find what your ESP32 (ESP-IDF) firmware left unlocked before you ship it.")
    ap.add_argument("project", nargs="?", default=".", help="ESP-IDF project folder (or an sdkconfig file)")
    ap.add_argument("--profile", choices=["release", "dev"], default="release",
                    help="dev reports chip lockdown settings (secure boot, flash encryption...) as info")
    ap.add_argument("--fail-on", choices=SEVERITIES[:4] + ["never"], default="high", help="lowest severity that makes the exit code 1 (default high)")
    ap.add_argument("--ignore", default="", help="comma-separated rule IDs to skip, e.g. PF012,PF108")
    ap.add_argument("--json", metavar="FILE", help="also write a JSON report")
    ap.add_argument("--html", metavar="FILE", help="also write an HTML report")
    ap.add_argument("--list-rules", action="store_true", help="print every rule and exit")
    ap.add_argument("--version", action="version", version=f"preflash {__version__}")
    a = ap.parse_args(argv)

    if a.list_rules:
        print(list_rules())
        return 0
    project = Path(a.project)
    if not project.exists():
        print(f"preflash: {project} does not exist", file=sys.stderr)
        return 2
    findings, meta = scan(project, a.profile, [x for x in a.ignore.split(",") if x.strip()])
    if meta["config"] is None and project.is_dir() and not any(project.glob("**/CMakeLists.txt")):
        print("preflash: no sdkconfig, sdkconfig.defaults or CMakeLists.txt here. Is this an ESP-IDF project?", file=sys.stderr)
        return 2
    print(report.to_text(findings, meta))
    if a.json:
        Path(a.json).write_text(report.to_json(findings, meta), encoding="utf-8")
    if a.html:
        Path(a.html).write_text(report.to_html(findings, meta), encoding="utf-8")
    if a.fail_on == "never":
        return 0
    return 1 if any(RANK[f.severity] <= RANK[a.fail_on] for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
