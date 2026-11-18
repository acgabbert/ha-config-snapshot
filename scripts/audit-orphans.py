#!/usr/bin/env python3
"""Report things that exist in Home Assistant but nothing provides or uses.

The reverse of audit-dead-references.py: registry entries whose source is
gone, helpers and scripts nothing calls, disabled integrations, and empty
devices, areas, and floors. Each one is a cleanup candidate, not a fault.

Reads only the snapshot in config/ and writes reports/orphans.md.
Never connects to Home Assistant.

    .venv/bin/python scripts/audit-orphans.py          # write the report
    .venv/bin/python scripts/audit-orphans.py --check  # also exit 1 on stale registry entries
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import snapshot  # noqa: E402

REPORT = snapshot.REPO / "reports" / "orphans.md"

# UI helpers kept in .storage/<domain>; registry unique_id is the item's id.
HELPER_DOMAINS = (
    "counter", "input_boolean", "input_button", "input_datetime", "input_number",
    "input_select", "input_text", "schedule", "timer",
)
# Platforms with no config entry whose source is not captured, so a missing
# source cannot be told from an uncaptured one.
UNCAPTURED_PLATFORMS = {
    "person": "`.storage/person` is not captured",
    "zone": "`.storage/zone` is not captured",
    "tag": "`.storage/tag` is not captured",
}
# The energy integration names cost sensors after their source:
# "<source registry id or entity_id>_grid_cost" and similar.
ENERGY_SUFFIXES = (
    "_grid_cost", "_grid_compensation", "_gas_cost", "_water_cost",
)


def table(header: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["None.", ""]
    out = ["| " + " | ".join(header) + " |", "|" + " --- |" * len(header)]
    out += ["| " + " | ".join(c.replace("|", "\\|") for c in r) + " |" for r in rows]
    return out + [""]


def yaml_unique_ids() -> set[str]:
    """Every `unique_id` value in the captured YAML."""
    ids = set()
    for file, root, _ in snapshot.reference_sources():
        if not file.endswith(".yaml"):
            continue
        for s in snapshot.iter_scalars(root, file):
            if not s.is_key and s.key == "unique_id":
                ids.add(s.value)
    return ids


def top_level_ids(name: str, key: str | None) -> set[str]:
    """IDs of the top-level items in a YAML list (by `key`) or mapping (its keys)."""
    path = snapshot.CONFIG / name
    root = snapshot.compose(path) if path.exists() else None
    if isinstance(root, yaml.MappingNode):
        return {k.value for k, _ in root.value}
    if isinstance(root, yaml.SequenceNode) and key:
        return {
            v for item in root.value
            if (v := snapshot.scalar_value(snapshot.node_get(item, key)))
        }
    return set()


def helper_items() -> dict[str, dict[str, dict]]:
    """{domain: {id: item}} for UI helpers in .storage."""
    out = {}
    for domain in HELPER_DOMAINS:
        if (snapshot.STORAGE / domain).exists():
            out[domain] = {i["id"]: i for i in snapshot.load_json(domain).get("items", [])}
    return out


def stale_registry_entries(entities, helpers):
    """Registry entries with no config entry whose YAML or .storage source is gone.

    HA keeps these as "restored" entities that are always unavailable.
    Returns (stale, unverifiable): [(entity, why)].
    """
    uids = yaml_unique_ids()
    sources = {
        "automation": (top_level_ids("automations.yaml", "id"), "`automations.yaml`"),
        "script": (top_level_ids("scripts.yaml", None), "`scripts.yaml`"),
        "homeassistant": (top_level_ids("scenes.yaml", "id"), "`scenes.yaml`"),
    }
    by_reg_id = {e["id"] for e in entities.values()}

    def in_yaml(uid: str) -> bool:
        # Template entities inside a block with its own unique_id are
        # registered as "<block>-<entity>".
        return uid in uids or any(
            uid.startswith(u + "-") and uid[len(u) + 1:] in uids for u in uids
        )

    stale, unverifiable = [], []
    for e in sorted(entities.values(), key=lambda e: e["entity_id"]):
        if e["config_entry_id"]:
            continue
        platform, uid = e["platform"], str(e["unique_id"])
        if platform in UNCAPTURED_PLATFORMS:
            unverifiable.append((e, UNCAPTURED_PLATFORMS[platform]))
        elif platform == "energy":
            source = next(
                (uid[: -len(s)] for s in ENERGY_SUFFIXES if uid.endswith(s)), None
            )
            if source is None:
                unverifiable.append((e, "unrecognized energy unique_id"))
            elif source not in by_reg_id and source not in entities:
                stale.append((e, f"energy cost sensor; source `{source}` is not in the registry"))
        elif platform in sources:
            ids, where = sources[platform]
            if uid not in ids:
                stale.append((e, f"no item with this ID in {where}"))
        elif platform in HELPER_DOMAINS:
            if uid not in helpers.get(platform, {}):
                stale.append((e, f"not in `.storage/{platform}`"))
        elif not in_yaml(uid):
            stale.append((e, f"no `{platform}` YAML with `unique_id: {uid}`"))
    return stale, unverifiable


def usage(entities) -> dict[str, set[str]]:
    """{entity_id: owners that reference it or call it as an action}."""
    used: dict[str, set[str]] = defaultdict(set)
    for r in snapshot.iter_references():
        if r.kind == "entity":
            used[r.target].add(r.owner)
    for c in snapshot.iter_action_calls():
        if c.domain == "script":
            used[c.target].add(c.owner)
    # A script calling itself is not a use.
    for target in list(used):
        used[target].discard(target)
    return used


def name_of(e: dict) -> str:
    return e.get("name") or e.get("original_name") or ""


def device_name(d: dict) -> str:
    return d.get("name_by_user") or d.get("name") or d["id"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if stale registry entries are found"
    )
    args = parser.parse_args()

    entities = snapshot.entity_registry()
    devices = snapshot.device_registry()
    areas = snapshot.area_registry()
    floors = {f["floor_id"]: f for f in snapshot.load_json("core.floor_registry")["floors"]}
    entries = {e["entry_id"]: e for e in snapshot.config_entries()}
    helpers = helper_items()
    used = usage(entities)

    stale, stale_unverifiable = stale_registry_entries(entities, helpers)
    stale_ids = {e["entity_id"] for e, _ in stale}

    def unused(domains) -> list[dict]:
        return [
            e for eid, e in sorted(entities.items())
            if eid.split(".")[0] in domains
            and eid not in stale_ids
            and not used.get(eid)
        ]

    unused_helpers = unused(HELPER_DOMAINS)
    unused_scripts = unused({"script"})
    unused_scenes = unused({"scene"})

    disabled_entries = [e for e in entries.values() if e["disabled_by"]]
    entry_entities = Counter(e["config_entry_id"] for e in entities.values())
    entry_devices = Counter(d["config_entry_id"] for d in devices.values())

    user_disabled = [
        e for _, e in sorted(entities.items())
        if e["disabled_by"] == "user"
    ]
    user_disabled_devices = [
        d for d in sorted(devices.values(), key=device_name)
        if d["disabled_by"] == "user"
    ]

    device_entities = Counter(e["device_id"] for e in entities.values() if e["device_id"])
    empty_devices = [
        d for d in sorted(devices.values(), key=device_name)
        if not device_entities[d["id"]]
    ]

    area_devices = Counter(d["area_id"] for d in devices.values() if d["area_id"])
    area_entities = Counter(e["area_id"] for e in entities.values() if e["area_id"])
    empty_areas = [
        a for a in sorted(areas.values(), key=lambda a: a["name"])
        if not area_devices[a["id"]] and not area_entities[a["id"]]
    ]
    floor_areas = Counter(a["floor_id"] for a in areas.values() if a.get("floor_id"))
    empty_floors = [f for fid, f in sorted(floors.items()) if not floor_areas[fid]]

    def entry_label(entry_id: str | None) -> str:
        e = entries.get(entry_id or "")
        return f"{e['domain']} ({e['title']})" if e else ""

    lines = [
        "# Orphans",
        "",
        "Generated by `scripts/audit-orphans.py` from the snapshot in",
        "`config/`. Do not edit by hand; re-run the script after each import.",
        "",
        "The reverse of `dead-references.md`: things that exist but that nothing",
        "provides or uses. Each row is a cleanup candidate to confirm in Home",
        "Assistant, not a fault. \"Used\" means referenced from",
        "`configuration.yaml` and its includes, `automations.yaml`,",
        "`scripts.yaml`, `scenes.yaml`, or a Lovelace dashboard. Not seen:",
        "voice assistants and Assist exposure, HomeKit and Alexa bridges,",
        "phone widgets and Siri shortcuts, Energy dashboard settings (an",
        "`input_number` price, for example), blueprint definitions,",
        "`python_scripts/`, and entity IDs built at runtime in templates.",
        "",
        "| Finding | Count |",
        "| --- | ---: |",
    ]
    summary = [
        ("Stale registry entries (source removed)", stale),
        ("Helpers nothing uses", unused_helpers),
        ("Scripts nothing calls", unused_scripts),
        ("Scenes nothing activates", unused_scenes),
        ("Disabled integrations", disabled_entries),
        ("Entities disabled by user", user_disabled),
        ("Devices disabled by user", user_disabled_devices),
        ("Devices with no entities (informational)", empty_devices),
        ("Areas with no devices or entities", empty_areas),
        ("Floors with no areas", empty_floors),
        ("Registry entries not verifiable from the snapshot (informational)",
         stale_unverifiable),
    ]
    for title, items in summary:
        lines.append(f"| {title} | {len(items)} |")
    lines.append("")

    lines += [
        "## Stale registry entries",
        "",
        "Entity registry entries with no config entry whose YAML or `.storage`",
        "source is gone: a deleted automation, script, scene, or helper, a",
        "removed or commented-out YAML platform, or an energy cost sensor whose",
        "metered entity was removed. HA shows these as unavailable with",
        "\"This entity is no longer being provided\". Delete them in",
        "**Settings → Entities** after confirming nothing else needs the ID.",
        "",
        "Rows with *Used by* filled are effectively dead references: the",
        "dead-references audit passes them because the registry still has the",
        "ID, but the entity has no state. They are listed first.",
        "",
    ]
    lines += table(
        ["Entity", "Platform", "Why", "Used by"],
        [
            [
                f"`{e['entity_id']}`", e["platform"], why,
                "<br>".join(sorted(used.get(e["entity_id"], ()))),
            ]
            for e, why in sorted(
                stale, key=lambda p: (not used.get(p[0]["entity_id"]), p[0]["entity_id"])
            )
        ],
    )

    lines += [
        "## Helpers nothing uses",
        "",
        "UI helpers with no reference. A helper toggled only from a dashboard",
        "*is* referenced; one used only by voice, a widget, or an external",
        "system is not, so check before deleting.",
        "",
    ]
    lines += table(
        ["Helper", "Name", "Disabled"],
        [
            [f"`{e['entity_id']}`", name_of(e)
             or helpers.get(e["platform"], {}).get(str(e["unique_id"]), {}).get("name", ""),
             e["disabled_by"] or ""]
            for e in unused_helpers
        ],
    )

    lines += [
        "## Scripts nothing calls",
        "",
        "Not called by an automation, another script, or a dashboard, and not",
        "referenced as an entity.",
        "",
    ]
    lines += table(
        ["Script", "Name"],
        [[f"`{e['entity_id']}`", name_of(e)] for e in unused_scripts],
    )

    lines += ["## Scenes nothing activates", ""]
    lines += table(
        ["Scene", "Name"],
        [[f"`{e['entity_id']}`", name_of(e)] for e in unused_scenes],
    )

    lines += [
        "## Disabled integrations",
        "",
        "Config entries that are disabled. Their devices and entities stay in",
        "the registries. Delete the integration if it is not coming back.",
        "",
    ]
    lines += table(
        ["Integration", "Title", "Disabled by", "Devices", "Entities"],
        [
            [e["domain"], e["title"], e["disabled_by"],
             str(entry_devices[e["entry_id"]]), str(entry_entities[e["entry_id"]])]
            for e in sorted(disabled_entries, key=lambda e: (e["domain"], e["title"]))
        ],
    )

    lines += [
        "## Entities and devices disabled by user",
        "",
        "Disabled by hand rather than by default. Either re-enable or delete;",
        "entities disabled by their integration (diagnostics and the like) are",
        "not listed.",
        "",
    ]
    lines += table(
        ["Entity or device", "Integration", "Used by"],
        [
            [f"`{e['entity_id']}`", entry_label(e["config_entry_id"]) or e["platform"],
             "<br>".join(sorted(used.get(e["entity_id"], ())))]
            for e in user_disabled
        ]
        + [
            [f"device '{device_name(d)}'", entry_label(d["config_entry_id"]), ""]
            for d in user_disabled_devices
        ],
    )

    lines += [
        "## Devices with no entities",
        "",
        "Often expected: bridges, hubs, and service devices that only parent",
        "other devices. A leaf device with no entities is usually left over",
        "from a re-pair.",
        "",
    ]
    lines += table(
        ["Device", "Integration", "Type", "Child devices"],
        [
            [
                device_name(d), entry_label(d["config_entry_id"]),
                d.get("entry_type") or "",
                str(sum(1 for x in devices.values() if x["via_device_id"] == d["id"])),
            ]
            for d in empty_devices
        ],
    )

    lines += ["## Areas with no devices or entities", ""]
    lines += table(
        ["Area", "Floor"],
        [[a["name"], a.get("floor_id") or ""] for a in empty_areas],
    )

    lines += ["## Floors with no areas", ""]
    lines += table(["Floor"], [[f["name"]] for f in empty_floors])

    lines += ["## Registry entries not verifiable from the snapshot", ""]
    lines += table(
        ["Entity", "Why"],
        [[f"`{e['entity_id']}`", why] for e, why in stale_unverifiable],
    )

    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    for title, items in summary:
        print(f"{len(items):4d}  {title}")
    print(f"wrote {REPORT.relative_to(snapshot.REPO)}")
    return 1 if args.check and stale else 0


if __name__ == "__main__":
    sys.exit(main())
