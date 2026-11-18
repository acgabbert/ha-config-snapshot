#!/usr/bin/env python3
"""Import a Home Assistant backup archive into config/.

Reads a backup .tar downloaded from Settings -> System -> Backups, opens the
Home Assistant core archive inside it (decrypting it if the backup is
protected), extracts an allowlist of paths, normalizes them, scans them for
sensitive values, and replaces config/ with the result.

It never writes to Home Assistant and never uses the network. Archive members
are read into memory by name and written only to allowlisted output paths;
nothing is extracted to disk by its archive path.

The archive layout (inner archive name, member prefix) is a Home Assistant
implementation detail. If it does not match what this script expects, the
script fails without writing anything.
"""

from __future__ import annotations

import argparse
import fnmatch
import getpass
import hashlib
import inspect
import json
import posixpath
import re
import shutil
import sys
import tarfile
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "config"

# --- Archive layout ---------------------------------------------------------

BACKUP_METADATA = "backup.json"
INNER_ARCHIVE_NAMES = ("homeassistant.tar.gz", "homeassistant.tar")
INNER_PREFIX = "data/"  # /config inside the core archive
MAX_MEMBER_BYTES = 50 * 1024 * 1024

# --- Allowlist (paths relative to /config) ----------------------------------

# The configurable part of the allowlist is import-allowlist.toml at the
# repository root. Everything below stays in code: what is never captured,
# and the files that are only ever written as summaries.
ALLOWLIST_FILE = REPO_ROOT / "import-allowlist.toml"


def load_allowlist(path: Path) -> tuple[tuple[str, ...], tuple[str, ...], frozenset[str], tuple[str, ...]]:
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
        yaml_cfg, storage_cfg = doc["yaml"], doc["storage"]
        entry_points = tuple(yaml_cfg["entry_points"])
        dirs = tuple(yaml_cfg["dirs"])
        exact = frozenset(storage_cfg["exact"])
        globs = tuple(storage_cfg["globs"])
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        sys.exit(f"error: cannot read allowlist {path}: {type(exc).__name__}: {exc}")
    for name in (*entry_points, *dirs, *exact, *globs):
        if not isinstance(name, str) or not name or name.startswith("/") or ".." in name.split("/"):
            sys.exit(f"error: {path}: invalid allowlist entry {name!r}")
    if any("/" in name for name in (*exact, *globs)):
        sys.exit(f"error: {path}: [storage] entries name files directly under .storage/; no '/' allowed")
    return entry_points, dirs, exact, globs


YAML_ENTRY_POINTS, YAML_DIRS, STORAGE_EXACT, STORAGE_GLOBS = load_allowlist(ALLOWLIST_FILE)
YAML_SUFFIXES = (".yaml", ".yml")

CONFIG_ENTRIES = "core.config_entries"
CONFIG_ENTRIES_OUTPUT = ".storage/core.config_entries.summary.json"
CONFIG_ENTRY_FIELDS = ("entry_id", "domain", "title", "source", "disabled_by")

CUSTOM_COMPONENT_MANIFEST = re.compile(r"^custom_components/([^/]+)/manifest\.json$")
MANIFEST_FIELDS = ("domain", "name", "version", "documentation", "issue_tracker")

# Never captured, whatever an !include or glob resolves to.
NEVER = (
    "secrets.yaml",
    "**/secrets.yaml",
    ".storage/auth*",
    ".storage/onboarding",
    ".storage/core.config",
    ".cloud/*",
)

# --- Normalization ----------------------------------------------------------

# Fields that change without a configuration change. Settle this set by
# importing two backups taken a day apart with no intended changes.
VOLATILE_KEYS = {"modified_at"}

# Tombstones of removed devices and entities. HA purges them on its own
# schedule, so they churn between imports, and they say nothing about the
# current configuration.
DROPPED_LISTS = {
    "core.device_registry": ("deleted_devices",),
    "core.entity_registry": ("deleted_entities",),
}

# Registry lists sorted by a stable ID so reordering is not a diff.
REGISTRY_SORT = {
    "core.device_registry": {"devices": "id"},
    "core.entity_registry": {"entities": "id"},
    "core.area_registry": {"areas": "id"},
    "core.floor_registry": {"floors": "floor_id"},
    "core.label_registry": {"labels": "label_id"},
}

# --- Sensitive-value scan ---------------------------------------------------

WEBHOOK_RE = re.compile(
    r"""(?P<lead>(?<![\w-])["']?webhook_id["']?\s*:\s*)(?P<q>["']?)(?P<val>[^"'\s,#}\]]+)(?P=q)""",
    re.IGNORECASE,
)
SECRET_KEY_RE = re.compile(
    r"""(?<![\w-])["']?(?P<key>token|access_token|refresh_token|api_key|apikey|"""
    r"""password|passwd|client_secret|secret|bearer_token|"""
    r"""code|pin|passcode|arm_code|disarm_code|code_arm|user_code|usercode)["']?\s*:\s*(?P<val>.*)$""",
    re.IGNORECASE,
)
AUTH_HEADER_RE = re.compile(r"""authorization["']?\s*:\s*["']?(bearer|basic)\s+\S""", re.IGNORECASE)
# URLs whose path or query string is itself the credential.
CREDENTIAL_URL_RE = re.compile(
    r"""(discord(?:app)?\.com/api/webhooks/"""
    r"""|hooks\.slack\.com/(?:services|workflows|triggers)/"""
    r"""|webhook\.office\.com/|\.logic\.azure\.com/.*[?&]sig="""
    r"""|api\.telegram\.org/bot\d"""
    r"""|https?://[^\s"'@/]+:[^\s"'@/]+@"""  # user:password@host
    r"""|https?://\S*[?&](?:token|access_token|api_key|apikey|key|secret|password|sig)=)""",
    re.IGNORECASE,
)
COORD_RE = re.compile(
    r"""(?<![\w-])["']?(latitude|longitude|lat|lon|lng)["']?\s*:\s*["']?-?\d{1,3}\.\d+""",
    re.IGNORECASE,
)
SAFE_VALUE_RE = re.compile(r"""^\s*(!secret\b|!env_var\b|["']?\{\{|["']?\{%|null\b|~|["']{2}\s*,?$|$)""")

# Personal identifiers with no audit value, always redacted. Emails get a
# stable hashed placeholder so the same address still matches across files.
EMAIL_RE = re.compile(r"""(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+""")
EMAIL_PLACEHOLDER_DOMAIN = "redacted.invalid"
SERIAL_KEY_RE = re.compile(r"""(?P<lead>"serial_number"\s*:\s*)"[^"]*\"""")
SERIAL_INLINE_RE = re.compile(r"""(?P<lead>\b(?:s/n|serial(?:\s*(?:no|number))?)\s*[:#]?\s*)(?P<val>[A-Za-z0-9][A-Za-z0-9_-]{5,})""", re.IGNORECASE)

INCLUDE_RE = re.compile(
    r"""!include(?P<kind>_dir_(?:list|named|merge_list|merge_named))?\s+(?P<q>["']?)(?P<path>[^"'\s#]+)(?P=q)"""
)


class ImportError_(Exception):
    """Raised for any condition where nothing must be written."""


@dataclass
class Finding:
    path: str
    line: int
    kind: str


# --- Archive reading --------------------------------------------------------


def password_to_key(password: str) -> bytes:
    """Supervisor's key derivation for SecureTar v1/v2 backups."""
    key = password.encode()
    for _ in range(100):
        key = hashlib.sha256(key).digest()
    return key[:16]


def read_outer(backup_path: Path, workdir: Path) -> tuple[dict, Path]:
    """Return backup.json and the path of the core archive copied to workdir."""
    with tarfile.open(backup_path, "r:*") as outer:
        names = {m.name.removeprefix("./"): m for m in outer.getmembers() if m.isreg()}
        if BACKUP_METADATA not in names:
            raise ImportError_(f"{BACKUP_METADATA} not found in {backup_path}; top-level members: {sorted(names)[:20]}")
        metadata = json.load(outer.extractfile(names[BACKUP_METADATA]))

        inner_name = next((n for n in INNER_ARCHIVE_NAMES if n in names), None)
        if inner_name is None:
            raise ImportError_(
                f"No Home Assistant core archive ({', '.join(INNER_ARCHIVE_NAMES)}) in backup; "
                f"members: {sorted(names)[:20]}. Was Home Assistant included in this backup?"
            )
        inner_path = workdir / inner_name
        with outer.extractfile(names[inner_name]) as src, open(inner_path, "wb") as dst:
            shutil.copyfileobj(src, dst)
    return metadata, inner_path


def open_inner(inner_path: Path, protected: bool, password: str | None):
    if not protected:
        return tarfile.open(inner_path, "r:*")
    try:
        from securetar import SecureTarFile
    except ImportError as exc:
        raise ImportError_("Backup is protected; install securetar (pip install -r scripts/requirements.txt)") from exc
    gzip = inner_path.name.endswith(".gz")
    params = inspect.signature(SecureTarFile.__init__).parameters
    if "password" in params:
        # Newer securetar derives the key itself and handles newer formats.
        return SecureTarFile(inner_path, "r", password=password, gzip=gzip)
    return SecureTarFile(inner_path, "r", key=password_to_key(password), gzip=gzip)


def read_config_tree(inner) -> tuple[dict[str, bytes], list[str]]:
    """Read candidate files under INNER_PREFIX into memory.

    Returns (files, all_paths): files maps /config-relative paths to bytes for
    every file that could be on the allowlist; all_paths lists every regular
    file seen, for the ignored-paths report.
    """
    files: dict[str, bytes] = {}
    all_paths: list[str] = []
    with inner as tar:
        for member in tar:  # streaming-safe: one pass, no random access
            if not member.isreg():
                continue
            name = member.name.removeprefix("./")
            if not name.startswith(INNER_PREFIX):
                continue
            rel = name[len(INNER_PREFIX):]
            all_paths.append(rel)
            if not is_candidate(rel) or member.size > MAX_MEMBER_BYTES:
                continue
            fileobj = tar.extractfile(member)
            if fileobj is not None:
                files[rel] = fileobj.read()
    if "configuration.yaml" not in files:
        sample = sorted(all_paths)[:20]
        raise ImportError_(
            f"{INNER_PREFIX}configuration.yaml not found in the core archive; "
            f"the archive layout may have changed. First paths under {INNER_PREFIX!r}: {sample}"
        )
    return files, all_paths


def is_candidate(rel: str) -> bool:
    if is_never(rel):
        return False
    if rel.endswith(YAML_SUFFIXES) and not rel.startswith((".storage/", "custom_components/")):
        return True
    if rel.startswith(".storage/") and "/" not in rel[len(".storage/"):]:
        return True
    return bool(CUSTOM_COMPONENT_MANIFEST.match(rel))


def is_never(rel: str) -> bool:
    return any(fnmatch.fnmatchcase(rel, pattern) for pattern in NEVER)


# --- Selection --------------------------------------------------------------


def resolve_includes(files: dict[str, bytes]) -> set[str]:
    """YAML files reachable from the entry points via !include*, plus YAML_DIRS."""
    selected: set[str] = set()
    queue = [p for p in YAML_ENTRY_POINTS if p in files]
    queue += [p for p in files if p.endswith(YAML_SUFFIXES) and p.split("/", 1)[0] in YAML_DIRS]
    while queue:
        rel = queue.pop()
        if rel in selected or is_never(rel):
            continue
        selected.add(rel)
        text = files[rel].decode("utf-8", errors="replace")
        base = posixpath.dirname(rel)
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            for match in INCLUDE_RE.finditer(line):
                target = posixpath.normpath(posixpath.join(base, match["path"]))
                if target.startswith("../") or target.startswith("/") or target == "..":
                    raise ImportError_(f"{rel}: !include target escapes /config: {match['path']}")
                if match["kind"]:
                    prefix = target.rstrip("/") + "/"
                    queue += [p for p in files if p.startswith(prefix) and p.endswith(YAML_SUFFIXES)]
                elif is_never(target):
                    print(f"note: {rel}: !include target is never captured: {target}", file=sys.stderr)
                elif target in files:
                    queue.append(target)
                else:
                    print(f"warning: {rel}: !include target not found in backup: {target}", file=sys.stderr)
    return selected


def select_storage(files: dict[str, bytes]) -> list[str]:
    out = []
    for rel in files:
        if not rel.startswith(".storage/"):
            continue
        name = rel[len(".storage/"):]
        if name in STORAGE_EXACT or any(fnmatch.fnmatchcase(name, g) for g in STORAGE_GLOBS):
            out.append(rel)
    return out


# --- Normalization ----------------------------------------------------------


def drop_volatile(obj):
    if isinstance(obj, dict):
        return {k: drop_volatile(v) for k, v in obj.items() if k not in VOLATILE_KEYS}
    if isinstance(obj, list):
        return [drop_volatile(v) for v in obj]
    return obj


def dump_json(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def normalize_storage(name: str, raw: bytes) -> bytes:
    doc = drop_volatile(json.loads(raw))
    data = doc.get("data")
    if isinstance(data, dict):
        for list_key in DROPPED_LISTS.get(name, ()):
            data.pop(list_key, None)
    for list_key, id_key in REGISTRY_SORT.get(name, {}).items():
        items = doc.get("data", {}).get(list_key)
        if isinstance(items, list):
            items.sort(key=lambda item: str(item.get(id_key, "")) if isinstance(item, dict) else "")
    return dump_json(doc)


def summarize_config_entries(raw: bytes) -> bytes:
    doc = json.loads(raw)
    entries = doc.get("data", {}).get("entries", [])
    summary = [{k: e.get(k) for k in CONFIG_ENTRY_FIELDS} for e in entries]
    summary.sort(key=lambda e: (str(e["domain"]), str(e["title"]), str(e["entry_id"])))
    return dump_json({"entries": summary})


def summarize_manifest(raw: bytes) -> bytes:
    doc = json.loads(raw)
    return dump_json({k: doc[k] for k in MANIFEST_FIELDS if k in doc})


# --- Scan -------------------------------------------------------------------


def webhook_placeholder(value: str) -> str:
    return "REDACTED_" + hashlib.sha256(value.encode()).hexdigest()[:16]


def redact_personal(data: bytes) -> tuple[bytes, dict[str, int]]:
    """Replace emails and serial numbers. Applied to every output file."""
    counts = {"email": 0, "serial number": 0}
    text = data.decode("utf-8", errors="replace")

    def email(m: re.Match) -> str:
        if m.group(0).endswith("@" + EMAIL_PLACEHOLDER_DOMAIN):
            return m.group(0)
        counts["email"] += 1
        digest = hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:12]
        return f"redacted-{digest}@{EMAIL_PLACEHOLDER_DOMAIN}"

    def serial_key(m: re.Match) -> str:
        counts["serial number"] += 1
        return f'{m["lead"]}"REDACTED"'

    def serial_inline(m: re.Match) -> str:
        if m["val"] == "REDACTED":
            return m.group(0)
        counts["serial number"] += 1
        return f"{m['lead']}REDACTED"

    text = EMAIL_RE.sub(email, text)
    text = SERIAL_KEY_RE.sub(serial_key, text)
    text = SERIAL_INLINE_RE.sub(serial_inline, text)
    return text.encode(), counts


def scan_and_redact(path: str, data: bytes, redact_webhooks: bool) -> tuple[bytes, list[Finding], int]:
    findings: list[Finding] = []
    redacted = 0
    lines = data.decode("utf-8", errors="replace").splitlines(keepends=True)
    for i, line in enumerate(lines, start=1):
        def replace_webhook(m: re.Match) -> str:
            nonlocal redacted
            val = m["val"]
            if val.startswith("!secret") or val.startswith("REDACTED_"):
                return m.group(0)
            if not redact_webhooks:
                findings.append(Finding(path, i, "webhook_id"))
                return m.group(0)
            redacted += 1
            return f"{m['lead']}{m['q']}{webhook_placeholder(val)}{m['q']}"

        line = WEBHOOK_RE.sub(replace_webhook, line)
        lines[i - 1] = line

        m = SECRET_KEY_RE.search(line)
        if m and not SAFE_VALUE_RE.match(m["val"]):
            findings.append(Finding(path, i, f"literal {m['key'].lower()}"))
        if AUTH_HEADER_RE.search(line):
            findings.append(Finding(path, i, "authorization header"))
        if CREDENTIAL_URL_RE.search(line):
            findings.append(Finding(path, i, "credential in URL"))
        if COORD_RE.search(line):
            findings.append(Finding(path, i, "coordinates"))
    return "".join(lines).encode(), findings, redacted


# --- Main -------------------------------------------------------------------


def read_key(args) -> str:
    if args.key_stdin:
        key = sys.stdin.readline().rstrip("\r\n")
    else:
        key = getpass.getpass("Backup encryption key: ")
    if not key:
        raise ImportError_("Empty backup encryption key")
    return key


def print_metadata(metadata: dict) -> None:
    print(f"Backup:          {metadata.get('name')} ({metadata.get('slug')})")
    print(f"Date:            {metadata.get('date')}")
    print(f"Home Assistant:  {metadata.get('homeassistant', {}).get('version') if isinstance(metadata.get('homeassistant'), dict) else metadata.get('homeassistant')}")
    print(f"Protected:       {metadata.get('protected')}")
    addons = metadata.get("addons") or []
    if addons:
        print("Add-ons in backup (not captured):")
        for addon in addons:
            print(f"  - {addon.get('name')} [{addon.get('slug')}] {addon.get('version')}")


def report_ignored(all_paths: list[str], written: set[str]) -> None:
    top_level: dict[str, int] = {}
    storage: list[str] = []
    for rel in all_paths:
        if rel in written or is_never(rel):
            continue
        if rel.startswith(".storage/") and "/" not in rel[len(".storage/"):]:
            if rel != f".storage/{CONFIG_ENTRIES}":
                storage.append(rel[len(".storage/"):])
            continue
        head = rel.split("/", 1)[0] + ("/" if "/" in rel else "")
        top_level[head] = top_level.get(head, 0) + 1
    if top_level:
        print("Not captured (top level of /config, file counts):")
        for head in sorted(top_level):
            print(f"  {head} ({top_level[head]})")
    if storage:
        print("Not captured (.storage):")
        for name in sorted(storage):
            print(f"  {name}")


def run(args) -> int:
    backup = Path(args.backup).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    if not backup.is_file():
        raise ImportError_(f"Backup not found: {backup}")

    with tempfile.TemporaryDirectory(prefix="ha-import-") as tmp:
        workdir = Path(tmp)
        metadata, inner_path = read_outer(backup, workdir)
        print_metadata(metadata)
        protected = bool(metadata.get("protected"))
        password = read_key(args) if protected else None

        try:
            files, all_paths = read_config_tree(open_inner(inner_path, protected, password))
        except ImportError_:
            raise
        except Exception as exc:  # wrong key, corrupt archive, unsupported format
            raise ImportError_(f"Could not read the core archive ({type(exc).__name__}: {exc}). Wrong key?") from exc
        inner_path.unlink()

        out: dict[str, bytes] = {}
        for rel in resolve_includes(files):
            out[rel] = files[rel]
        for rel in select_storage(files):
            out[rel] = normalize_storage(rel[len(".storage/"):], files[rel])
        if f".storage/{CONFIG_ENTRIES}" in files:
            out[CONFIG_ENTRIES_OUTPUT] = summarize_config_entries(files[f".storage/{CONFIG_ENTRIES}"])
        for rel, raw in files.items():
            if CUSTOM_COMPONENT_MANIFEST.match(rel):
                out[rel] = summarize_manifest(raw)

        leaked = sorted(rel for rel in out if is_never(rel))
        if leaked:
            raise ImportError_(f"Refusing to write never-captured paths: {leaked}")

        findings: list[Finding] = []
        redacted_total = 0
        personal_totals = {"email": 0, "serial number": 0}
        for rel in sorted(out):
            out[rel], counts = redact_personal(out[rel])
            for kind, n in counts.items():
                personal_totals[kind] += n
            out[rel], file_findings, redacted = scan_and_redact(rel, out[rel], args.redact_webhook_ids)
            findings += file_findings
            redacted_total += redacted
        if redacted_total:
            print(f"Redacted {redacted_total} webhook ID(s) with hashed placeholders.")
        for kind, n in personal_totals.items():
            if n:
                print(f"Redacted {n} {kind}(s).")
        if findings:
            print("Sensitive-value scan failed; nothing written:", file=sys.stderr)
            for f in findings:
                print(f"  {f.path}:{f.line}: {f.kind}", file=sys.stderr)
            return 2

        staging = workdir / "config"
        for rel, data in out.items():
            dest = staging / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        report_ignored(all_paths, set(out) | {rel for rel in files if CUSTOM_COMPONENT_MANIFEST.match(rel)})

        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(staging, output)

    print(f"Wrote {len(out)} files to {output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("backup", help="Backup .tar downloaded from Settings -> System -> Backups")
    parser.add_argument("--key-stdin", action="store_true", help="Read the backup encryption key from the first line of stdin")
    parser.add_argument("--redact-webhook-ids", action="store_true", help="Replace webhook IDs with hashed placeholders instead of failing")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help=argparse.SUPPRESS)  # for tests
    args = parser.parse_args()
    sys.stdout.reconfigure(line_buffering=True)  # keep stdout/stderr in order
    try:
        return run(args)
    except ImportError_ as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
