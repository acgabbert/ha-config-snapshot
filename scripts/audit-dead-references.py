#!/usr/bin/env python3
"""Report references to entities, devices, areas, and actions that do not exist or are disabled.

Reads only the snapshot in config/ and writes reports/dead-references.md.
Never connects to Home Assistant.

    .venv/bin/python scripts/audit-dead-references.py          # write the report
    .venv/bin/python scripts/audit-dead-references.py --check  # also exit 1 on findings
"""

from __future__ import annotations

import argparse
import difflib
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import snapshot  # noqa: E402

REPORT = snapshot.REPO / "reports" / "dead-references.md"


def suggest(target: str, known: list[str]) -> str:
    domain = target.split(".")[0]
    same_domain = [e for e in known if e.startswith(domain + ".")]
    match = difflib.get_close_matches(target, same_domain, n=1, cutoff=0.75)
    return f"`{match[0]}`" if match else ""


# Integrations loaded without a config entry or their own YAML key: HA core,
# HAOS, and the members of `default_config:`.
ALWAYS_LOADED = frozenset(
    """
    homeassistant persistent_notification system_log logger frontend recorder
    hassio http api
    """.split()
)
DEFAULT_CONFIG = frozenset(
    """
    assist_pipeline backup bluetooth cloud conversation dhcp energy go2rtc
    history homeassistant_alerts image_upload logbook media_source mobile_app
    my ssdp stream sun usb webhook zeroconf zone
    """.split()
)
# Domain-level actions that take a target rather than naming one.
DOMAIN_ACTIONS = {
    "script": {"turn_on", "turn_off", "toggle", "reload"},
    "automation": {"trigger", "turn_on", "turn_off", "toggle", "reload"},
    "notify": {"notify", "send_message", "persistent_notification"},
    "rest_command": {"reload"},
}
# Domains whose providers are not captured, so their actions cannot be checked.
UNVERIFIABLE = {"python_script": "`python_scripts/` is not captured"}


def classify_actions(calls, entities, yaml_scripts):
    """Split action calls into (problems, unverifiable).

    problems: [(call, problem, closest-match)]; unverifiable: [(call, reason)].
    """
    entries = snapshot.config_entries()
    enabled_domains = {e["domain"] for e in entries if not e["disabled_by"]}
    disabled_domains = {e["domain"] for e in entries} - enabled_domains
    available = (
        ALWAYS_LOADED
        | (DEFAULT_CONFIG if "default_config" in snapshot.yaml_integrations() else set())
        | snapshot.yaml_integrations()
        | snapshot.custom_component_domains()
        | enabled_domains
    )
    phones = snapshot.mobile_app_notify_services()
    live_phones = [f"notify.{n}" for n, d in phones.items() if not d.get("disabled_by")]
    rest_commands = snapshot.yaml_section_keys("rest_command")
    scripts = sorted({e for e in entities if e.startswith("script.")}
                     | {f"script.{k}" for k in yaml_scripts})

    problems, unverifiable = [], []
    for c in calls:
        if c.domain in UNVERIFIABLE:
            unverifiable.append((c, UNVERIFIABLE[c.domain]))
            continue
        if c.name in DOMAIN_ACTIONS.get(c.domain, ()):
            continue
        if c.domain == "script":
            if c.target in entities and entities[c.target]["disabled_by"]:
                problems.append((c, f"script disabled by {entities[c.target]['disabled_by']}", ""))
            elif c.target not in scripts:
                problems.append((c, "no such script", suggest(c.target, scripts)))
        elif c.domain == "notify" and c.name.startswith("mobile_app_"):
            device = phones.get(c.name)
            if device is None:
                problems.append((
                    c, "no mobile_app device with this name",
                    suggest(c.target, live_phones),
                ))
            elif device.get("disabled_by"):
                problems.append((c, f"device disabled by {device['disabled_by']}", ""))
        elif c.domain == "notify":
            problems.append((
                c, "not a mobile_app device; no YAML notify platform or group captured",
                suggest(c.target, [f"notify.{n}" for n in phones]),
            ))
        elif c.domain == "rest_command":
            if c.name not in rest_commands:
                problems.append((
                    c, "no such rest_command",
                    suggest(c.target, [f"rest_command.{n}" for n in rest_commands]),
                ))
        elif c.domain in snapshot.ENTITY_DOMAINS or c.domain in available:
            continue
        elif c.domain in disabled_domains:
            problems.append((c, "integration disabled", ""))
        else:
            problems.append((c, "integration not set up", ""))
    return problems, unverifiable


def table(header: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["None.", ""]
    out = ["| " + " | ".join(header) + " |", "|" + " --- |" * len(header)]
    out += ["| " + " | ".join(c.replace("|", "\\|") for c in r) + " |" for r in rows]
    return out + [""]


def grouped(refs, key) -> dict[str, list]:
    groups: dict[str, list] = defaultdict(list)
    for r in refs:
        groups[key(r)].append(r)
    return dict(sorted(groups.items()))


def locations(refs) -> str:
    seen = []
    for r in sorted(refs, key=lambda r: (r.file, r.line)):
        loc = f"`{r.file}:{r.line}` {r.owner}"
        if loc not in seen:
            seen.append(loc)
    return "<br>".join(seen)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if anything is found")
    args = parser.parse_args()

    entities = snapshot.entity_registry()
    devices = snapshot.device_registry()
    areas = snapshot.area_registry()
    yaml_defined = snapshot.yaml_defined_entities()
    known_ids = sorted(set(entities) | set(yaml_defined) | snapshot.BUILTIN_ENTITIES)

    refs = list(snapshot.iter_references())
    entity_refs = [r for r in refs if r.kind == "entity"]

    missing = [
        r for r in entity_refs
        if r.target not in entities
        and r.target not in yaml_defined
        and r.target not in snapshot.BUILTIN_ENTITIES
    ]
    disabled = [
        r for r in entity_refs
        if r.target in entities and entities[r.target]["disabled_by"]
    ]
    via_yaml = [
        r for r in entity_refs if r.target not in entities and r.target in yaml_defined
    ]
    missing_devices = [
        r for r in refs if r.kind == "device" and r.target not in devices
    ]
    disabled_devices = [
        r for r in refs
        if r.kind == "device" and r.target in devices and devices[r.target]["disabled_by"]
    ]
    missing_areas = [r for r in refs if r.kind == "area" and r.target not in areas]

    scripts_root = snapshot.compose(snapshot.CONFIG / "scripts.yaml")
    yaml_scripts = {k.value for k, _ in getattr(scripts_root, "value", [])}
    action_problems, action_unverifiable = classify_actions(
        snapshot.iter_action_calls(), entities, yaml_scripts
    )
    dead_actions = [c for c, _, _ in action_problems]
    unverified_actions = [c for c, _ in action_unverifiable]

    lines = [
        "# Dead references",
        "",
        "Generated by `scripts/audit-dead-references.py` from the snapshot in",
        "`config/`. Do not edit by hand; re-run the script after each import.",
        "",
        "Scanned: `configuration.yaml` and its YAML includes, `automations.yaml`",
        "(including blueprint inputs), `scripts.yaml`, `scenes.yaml`, and every",
        "Lovelace dashboard. Entity IDs are found in reference keys and inside",
        "templates; actions are the literal `domain.name` values of `action:`,",
        "`service:`, and `perform_action:` keys. Not scanned: blueprint",
        "definitions, `python_scripts/` (not captured), and entity IDs built",
        "at runtime in templates",
        "(`'sensor.' ~ name`) or templated actions.",
        "",
        "| Finding | References | Distinct targets |",
        "| --- | ---: | ---: |",
    ]
    summary = [
        ("Entities missing from the registry", missing),
        ("Entities disabled in the registry", disabled),
        ("Devices missing from the registry", missing_devices),
        ("Devices disabled in the registry", disabled_devices),
        ("Areas missing from the registry", missing_areas),
        ("Actions with no provider", dead_actions),
        ("Actions not verifiable from the snapshot (informational)", unverified_actions),
        ("Entities defined in YAML without `unique_id` (informational)", via_yaml),
    ]
    for title, items in summary:
        lines.append(f"| {title} | {len(items)} | {len({r.target for r in items})} |")
    lines.append("")

    lines += [
        "## Entities missing from the registry",
        "",
        "Not in `core.entity_registry`, not defined in YAML, and not built in",
        "(`zone.home`, `sun.sun`). Usually a renamed or removed entity: the",
        "reference is broken or silently inert. *Closest match* is a same-domain",
        "registry ID with a similar name, offered as a lead, not a fix.",
        "",
    ]
    lines += table(
        ["Entity", "Closest match", "Referenced at"],
        [
            [f"`{t}`", suggest(t, known_ids), locations(rs)]
            for t, rs in grouped(missing, lambda r: r.target).items()
        ],
    )

    lines += [
        "## Entities disabled in the registry",
        "",
        "Disabled entities have no state, so triggers never fire and conditions",
        "never pass.",
        "",
    ]
    lines += table(
        ["Entity", "Disabled by", "Referenced at"],
        [
            [f"`{t}`", entities[t]["disabled_by"], locations(rs)]
            for t, rs in grouped(disabled, lambda r: r.target).items()
        ],
    )

    lines += ["## Devices missing or disabled", ""]
    lines += table(
        ["Device ID", "Problem", "Referenced at"],
        [
            [f"`{t}`", "missing", locations(rs)]
            for t, rs in grouped(missing_devices, lambda r: r.target).items()
        ]
        + [
            [
                f"`{t}` ({devices[t].get('name_by_user') or devices[t].get('name')})",
                f"disabled by {devices[t]['disabled_by']}",
                locations(rs),
            ]
            for t, rs in grouped(disabled_devices, lambda r: r.target).items()
        ],
    )

    lines += ["## Areas missing from the registry", ""]
    lines += table(
        ["Area ID", "Referenced at"],
        [
            [f"`{t}`", locations(rs)]
            for t, rs in grouped(missing_areas, lambda r: r.target).items()
        ],
    )

    lines += [
        "## Actions with no provider",
        "",
        "An action call that nothing provides raises an error when it runs, which",
        "stops the automation or script at that step unless the step sets",
        "`continue_on_error`. Phone notify actions are resolved against",
        "`mobile_app` device names in the device registry; other domains",
        "against config entries, `configuration.yaml`, `default_config`, and",
        "custom components.",
        "",
    ]
    by_target = grouped(action_problems, lambda p: p[0].target)
    lines += table(
        ["Action", "Problem", "Closest match", "Called at"],
        [
            [f"`{t}`", ps[0][1], ps[0][2], locations([c for c, _, _ in ps])]
            for t, ps in by_target.items()
        ],
    )

    lines += ["## Actions not verifiable from the snapshot", ""]
    lines += table(
        ["Action", "Why", "Called at"],
        [
            [f"`{t}`", ps[0][1], locations([c for c, _ in ps])]
            for t, ps in grouped(action_unverifiable, lambda p: p[0].target).items()
        ],
    )

    lines += [
        "## Entities defined in YAML without `unique_id`",
        "",
        "These resolve, but only because the script derived their IDs from the",
        "YAML `name`. They cannot be renamed, given an area, or disabled in the",
        "UI. Adding a `unique_id` puts them in the registry.",
        "",
    ]
    lines += table(
        ["Entity", "Defined at", "References"],
        [
            [f"`{t}`", f"`{yaml_defined[t]}`", str(len(rs))]
            for t, rs in grouped(via_yaml, lambda r: r.target).items()
        ],
    )

    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    for title, items in summary:
        print(f"{len({r.target for r in items}):4d}  {title}")
    print(f"wrote {REPORT.relative_to(snapshot.REPO)}")

    problems = (
        missing or disabled or missing_devices or disabled_devices or missing_areas
        or dead_actions
    )
    return 1 if args.check and problems else 0


if __name__ == "__main__":
    sys.exit(main())
