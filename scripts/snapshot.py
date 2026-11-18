"""Read-only access to the Home Assistant snapshot in config/.

Shared by the audit and inventory scripts. Nothing here touches Home Assistant
or the network; it only parses files the importer wrote.

YAML is walked as a node tree (yaml.compose) rather than constructed, so custom
tags such as !secret, !input, and !include need no constructors and every
scalar keeps its line number.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "config"
STORAGE = CONFIG / ".storage"

# Entity domains HA can create. Used to find entity IDs inside free text
# (templates), where a looser pattern would match service names and URLs.
ENTITY_DOMAINS = frozenset(
    """
    ai_task alarm_control_panel assist_satellite automation binary_sensor
    button calendar camera climate conversation counter cover date datetime
    device_tracker event fan group humidifier image image_processing
    input_boolean input_button input_datetime input_number input_select
    input_text lawn_mower light lock media_player notify number person
    remote scene schedule script select sensor siren stt sun switch tag
    text time timer todo tts update vacuum valve wake_word water_heater
    weather zone
    """.split()
)

# Entities HA creates without a registry entry.
BUILTIN_ENTITIES = frozenset({"zone.home", "sun.sun"})

ENTITY_ID_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_DOMAIN_ALT = "|".join(sorted(ENTITY_DOMAINS, key=len, reverse=True))
# The lookbehind keeps "binary_sensor.x" from also matching as "sensor.x".
# "states.sensor.x" is consumed whole, yielding "sensor.x".
ENTITY_IN_TEXT_RE = re.compile(
    rf"(?<![\w])(?:states\.)?((?:{_DOMAIN_ALT})\.[a-z0-9_]+)(?![\w(])"
)
DEVICE_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# Keys whose scalar values are never entity references: service/action names,
# integration names, display text, and IDs of the item itself.
NON_REFERENCE_KEYS = frozenset(
    {
        "action",
        "alias",
        "condition",  # condition type, e.g. zone.occupancy_is_not_detected
        "description",
        "domain",
        "icon",
        "id",
        "name",
        "path",
        "perform_action",
        "platform",
        "service",
        "title",
        "trigger",  # trigger platform, e.g. event.received
        "type",
        "unique_id",
        "url",
        "url_path",
    }
)


@dataclass(frozen=True)
class Scalar:
    """One scalar from a YAML/JSON file, with where it was found."""

    file: str  # repository-relative path
    line: int
    path: tuple  # keys and list indexes from the document root
    value: str
    tag: str
    is_key: bool = False

    @property
    def key(self) -> str | None:
        """The nearest mapping key above this scalar."""
        for part in reversed(self.path):
            if isinstance(part, str):
                return part
        return None


def rel(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def compose(path: Path):
    with path.open(encoding="utf-8") as f:
        return yaml.compose(f, Loader=yaml.SafeLoader)


def iter_scalars(node, file: str, path: tuple = ()) -> Iterator[Scalar]:
    if node is None:
        return
    if isinstance(node, yaml.ScalarNode):
        yield Scalar(file, node.start_mark.line + 1, path, node.value, node.tag)
    elif isinstance(node, yaml.SequenceNode):
        for i, child in enumerate(node.value):
            yield from iter_scalars(child, file, path + (i,))
    elif isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            key = k.value if isinstance(k, yaml.ScalarNode) else str(k.start_mark)
            if isinstance(k, yaml.ScalarNode):
                yield Scalar(
                    file, k.start_mark.line + 1, path, k.value, k.tag, is_key=True
                )
            yield from iter_scalars(v, file, path + (key,))


def node_get(node, *path):
    """Follow mapping keys / list indexes through a composed node tree."""
    for part in path:
        if isinstance(node, yaml.MappingNode) and isinstance(part, str):
            node = next(
                (v for k, v in node.value if getattr(k, "value", None) == part), None
            )
        elif isinstance(node, yaml.SequenceNode) and isinstance(part, int):
            node = node.value[part] if part < len(node.value) else None
        else:
            return None
        if node is None:
            return None
    return node


def scalar_value(node) -> str | None:
    return node.value if isinstance(node, yaml.ScalarNode) else None


def load_json(name: str):
    return json.loads((STORAGE / name).read_text(encoding="utf-8"))["data"]


def entity_registry() -> dict[str, dict]:
    return {e["entity_id"]: e for e in load_json("core.entity_registry")["entities"]}


def device_registry() -> dict[str, dict]:
    return {d["id"]: d for d in load_json("core.device_registry")["devices"]}


def area_registry() -> dict[str, dict]:
    return {a["id"]: a for a in load_json("core.area_registry")["areas"]}


def slugify(text: str) -> str:
    """Approximates HA's slugify for ASCII names.

    Apostrophes are dropped rather than turned into separators, as HA does:
    "Alex’s iPhone" becomes "alexs_iphone".
    """
    text = re.sub(r"['’]", "", text.lower())
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _is_template(text: str) -> bool:
    return "{{" in text or "{%" in text


def yaml_defined_entities() -> dict[str, str]:
    """Entity IDs defined in YAML without a unique_id, so absent from the registry.

    Returns {entity_id: "file:line"}. IDs are derived from `name` with an
    approximation of HA's slugify; entities with a unique_id are in the
    registry already and are not listed.
    """
    found: dict[str, str] = {}

    def add(domain: str, item) -> None:
        if not isinstance(item, yaml.MappingNode) or node_get(item, "unique_id"):
            return
        explicit = scalar_value(node_get(item, "default_entity_id"))
        name = scalar_value(node_get(item, "name"))
        if explicit:
            eid = explicit
        elif name and not _is_template(name):
            eid = f"{domain}.{slugify(name)}"
        else:
            return
        found.setdefault(eid, f"{rel(path)}:{item.start_mark.line + 1}")

    # template.yaml: list of {<domain>: [entities], trigger: ...}
    path = CONFIG / "templates.yaml"
    if path.exists() and (root := compose(path)) is not None:
        for block in getattr(root, "value", []):
            for k, v in getattr(block, "value", []):
                if k.value in ENTITY_DOMAINS and isinstance(v, yaml.SequenceNode):
                    for item in v.value:
                        add(k.value, item)

    # sensor: list of platform entries
    path = CONFIG / "sensors.yaml"
    if path.exists() and (root := compose(path)) is not None:
        for item in getattr(root, "value", []):
            add("sensor", item)

    # mqtt: {<domain>: [entities]}
    path = CONFIG / "mqtt.yaml"
    if path.exists() and (root := compose(path)) is not None:
        for k, v in getattr(root, "value", []):
            if k.value in ENTITY_DOMAINS and isinstance(v, yaml.SequenceNode):
                for item in v.value:
                    add(k.value, item)

    # configuration.yaml: <domain>: [platform entries]; remote_rpi_gpio names
    # its entities after the port labels.
    path = CONFIG / "configuration.yaml"
    root = compose(path)
    for k, v in getattr(root, "value", []):
        if k.value not in ENTITY_DOMAINS or not isinstance(v, yaml.SequenceNode):
            continue
        for item in v.value:
            ports = node_get(item, "ports")
            if isinstance(ports, yaml.MappingNode):
                for _, label in ports.value:
                    if scalar_value(label):
                        found.setdefault(
                            f"{k.value}.{slugify(label.value)}",
                            f"{rel(path)}:{label.start_mark.line + 1}",
                        )
            else:
                add(k.value, item)

    return found


# --- Reference sources --------------------------------------------------------

YAML_SOURCES = (
    "configuration.yaml",
    "automations.yaml",
    "scripts.yaml",
    "scenes.yaml",
    "templates.yaml",
    "sensors.yaml",
    "mqtt.yaml",
)


def _yaml_owner(file: str, root, path: tuple) -> str:
    """A human label for the top-level item a reference sits in."""
    if not path:
        return file
    top = node_get(root, path[0])
    if file.endswith("scripts.yaml"):
        return f"script.{path[0]}"
    label = None
    for key in ("alias", "name", "id"):
        label = scalar_value(node_get(top, key))
        if label:
            break
    if file.endswith("automations.yaml"):
        return f"automation '{label}'"
    if file.endswith("scenes.yaml"):
        return f"scene '{label}'"
    if isinstance(path[0], str):
        return f"{path[0]}" + (f" '{label}'" if label else "")
    return f"item {path[0]}" + (f" '{label}'" if label else "")


def _lovelace_owner(dashboard: str, root, path: tuple) -> str:
    # path: ("data", "config", "views", i, ...)
    if len(path) >= 4 and path[2] == "views":
        view = node_get(root, *path[:4])
        title = scalar_value(node_get(view, "title")) or scalar_value(
            node_get(view, "path")
        )
        return f"dashboard '{dashboard}' view '{title or path[3]}'"
    return f"dashboard '{dashboard}'"


def dashboard_titles() -> dict[str, str]:
    titles = {"lovelace": "Overview"}
    path = STORAGE / "lovelace_dashboards"
    if path.exists():
        for item in load_json("lovelace_dashboards").get("items", []):
            titles[f"lovelace.{item['id']}"] = item.get("title", item["id"])
    return titles


def reference_sources() -> Iterator[tuple[str, object, callable]]:
    """Yield (file, composed root, owner_fn) for every file that can hold references."""
    for name in YAML_SOURCES:
        path = CONFIG / name
        if not path.exists():
            continue
        root = compose(path)
        file = rel(path)
        yield file, root, (lambda p, f=file, r=root: _yaml_owner(f, r, p))
    titles = dashboard_titles()
    for path in sorted(STORAGE.glob("lovelace*")):
        if path.name in ("lovelace_dashboards", "lovelace_resources"):
            continue
        # Pretty-printed JSON is valid YAML, and composing it keeps line numbers.
        root = compose(path)
        title = titles.get(path.name, path.name)
        yield rel(path), root, (lambda p, t=title, r=root: _lovelace_owner(t, r, p))


@dataclass(frozen=True)
class Reference:
    kind: str  # "entity", "device", or "area"
    target: str
    file: str
    line: int
    owner: str
    where: str  # key path inside the owner


def _fmt_path(path: tuple) -> str:
    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else part)
    return out


def iter_references() -> Iterator[Reference]:
    """Every entity, device, and area reference in the snapshot.

    Blueprint definitions are not scanned (their entity IDs are selectors and
    examples); blueprint *uses* in automations.yaml are, through their inputs.
    """
    for file, root, owner_fn in reference_sources():
        for s in iter_scalars(root, file):
            if s.tag != "tag:yaml.org,2002:str" or not s.value:
                continue  # !secret, !input, !include, and non-strings
            parent_path = s.path
            key = s.key
            if s.is_key:
                # Mapping keys are references only when they are a whole entity
                # ID, as in scene `entities:`.
                if ENTITY_ID_RE.match(s.value) and s.value.split(".")[0] in ENTITY_DOMAINS:
                    yield Reference(
                        "entity", s.value, file, s.line, owner_fn(parent_path),
                        _fmt_path(parent_path[1:]),
                    )
                continue
            if key in NON_REFERENCE_KEYS:
                continue
            owner = owner_fn(parent_path)
            where = _fmt_path(parent_path[1:])
            if key and "device" in key and DEVICE_ID_RE.match(s.value):
                yield Reference("device", s.value, file, s.line, owner, where)
                continue
            if key == "area_id":
                yield Reference("area", s.value, file, s.line, owner, where)
                continue
            for m in ENTITY_IN_TEXT_RE.finditer(s.value):
                yield Reference("entity", m.group(1), file, s.line, owner, where)


# --- Action (service) calls ---------------------------------------------------

# Keys whose value names the action to perform: `action:` in automations and
# scripts, `service:` (its pre-2024.8 name), and `perform_action:` /
# `service:` in dashboard tap actions.
ACTION_KEYS = frozenset({"action", "service", "perform_action"})
ACTION_RE = re.compile(r"^([a-z0-9_]+)\.([a-z0-9_]+)$")


@dataclass(frozen=True)
class ActionCall:
    domain: str
    name: str
    file: str
    line: int
    owner: str
    where: str

    @property
    def target(self) -> str:
        return f"{self.domain}.{self.name}"


def iter_action_calls() -> Iterator[ActionCall]:
    """Every literal `domain.name` action called from the snapshot.

    Templated actions (`action: "{{ ... }}"`), `!input` actions in blueprint
    uses, and dashboard action types (`more-info`, `call-service`) do not
    match ACTION_RE and are skipped.
    """
    for file, root, owner_fn in reference_sources():
        for s in iter_scalars(root, file):
            if s.is_key or s.key not in ACTION_KEYS:
                continue
            if s.tag != "tag:yaml.org,2002:str":
                continue
            m = ACTION_RE.match(s.value.strip())
            if not m:
                continue
            yield ActionCall(
                m.group(1), m.group(2), file, s.line, owner_fn(s.path),
                _fmt_path(s.path[1:]),
            )


def config_entries() -> list[dict]:
    path = STORAGE / "core.config_entries.summary.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))["entries"]


def yaml_integrations() -> set[str]:
    """Top-level integration keys in configuration.yaml."""
    root = compose(CONFIG / "configuration.yaml")
    return {k.value for k, _ in getattr(root, "value", [])}


def yaml_section_keys(domain: str) -> set[str]:
    """Keys of a mapping section in configuration.yaml, e.g. rest_command names."""
    node = node_get(compose(CONFIG / "configuration.yaml"), domain)
    if isinstance(node, yaml.MappingNode):
        return {k.value for k, _ in node.value}
    return set()


def custom_component_domains() -> set[str]:
    base = CONFIG / "custom_components"
    return {p.name for p in base.iterdir() if p.is_dir()} if base.exists() else set()


def mobile_app_notify_services() -> dict[str, dict]:
    """{"mobile_app_<slug>": device} for every mobile_app device.

    HA names a phone's legacy notify action after the device name the app
    registered with (the registry's `name`, not `name_by_user`).
    """
    out = {}
    for d in device_registry().values():
        if any(i[0] == "mobile_app" for i in d.get("identifiers", [])) and d.get("name"):
            out[f"mobile_app_{slugify(d['name'])}"] = d
    return out
