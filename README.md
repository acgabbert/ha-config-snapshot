# Home Assistant configuration snapshot

A template for keeping a reviewed, versioned, **read-only** copy of part of a
Home Assistant configuration in git, so that coding agents (Claude Code, Codex,
and similar) can inventory, audit, and propose cleanups to automations,
scripts, scenes, helpers, dashboards, and the device/entity/area model
**without any access to Home Assistant itself**.

The idea:

- Home Assistant stays authoritative. The repository is filled by importing a
  backup you downloaded; nothing here connects to or writes to Home Assistant.
- Secrets are kept out by construction: an allowlist of paths, summaries
  instead of credential-bearing files, a sensitive-value scan that blocks the
  import, and gitleaks as a second net.
- Agents read the snapshot and audit reports and propose changes as pull
  requests. You apply them in Home Assistant, take a new backup, and
  re-import. The diff confirms the change landed.
- `AGENTS.md` tells agents the rules: no live access, `config/` is generated,
  the allowlist is a review boundary.

## Before you start

- **Keep your repository private.** Even with secrets removed, the snapshot
  maps your home: device and room names, presence and alarm logic, MAC
  addresses, and LAN IPs. Create your repository from this template as
  private.
- **The scan is not a guarantee.** It catches common credential shapes, not
  every secret an integration might store in YAML. Review the first import by
  hand before you commit it, and review every diff after.
- **Agents still need limits.** `AGENTS.md` is an instruction, not a sandbox.
  If your agent can reach Home Assistant on the network, or a token is in its
  environment, the policy is all that stops it. Run agents where they have
  no Home Assistant credentials.

## Layout

| Path | Contents |
| --- | --- |
| `config/` | Snapshot written by the importer. Mirrors HA's `/config` for the captured paths only. Created on first import |
| `import-allowlist.toml` | Which YAML files and `.storage` files the importer captures |
| `scripts/import-backup.py` | Reads a backup archive, extracts the allowlist, normalizes, scans, writes `config/` |
| `scripts/snapshot.py` | Shared read-only parsing of `config/` for the audit scripts |
| `scripts/audit-*.py` | Audits that read only `config/` and write `reports/` |
| `reports/` | Generated audit reports. Regenerate after each import; do not edit by hand |
| `AGENTS.md` | Rules for agents working in this repository (`CLAUDE.md` imports it) |
| `INSTANCE.md` | Notes about your installation. Yours to edit; the template never changes it |

The snapshot lives in `config/` rather than at the repository root so the
importer can replace it wholesale without touching scripts or docs.

## What is captured

Only allowlisted paths. Anything else in `/config` is ignored and listed in the
importer's output so new files can be reviewed and added deliberately.

- The YAML entry points in `import-allowlist.toml` (by default
  `configuration.yaml`, `automations.yaml`, `scripts.yaml`, `scenes.yaml`) and
  every file or directory they reach through `!include` / `!include_dir_*`
  (recursively), plus `packages/` and `blueprints/`. `!secret` references are
  kept; `secrets.yaml` is never read.
- `custom_components/*/manifest.json`, reduced to domain, name, version, and
  source links. No integration code.
- `.storage` device, entity, area, floor, and label registries; UI helpers
  (`input_*`, `counter`, `timer`, `schedule`); dashboards (`lovelace*`). JSON is
  pretty-printed with sorted keys, volatile fields are dropped, and registry
  lists are sorted by ID. The registries' `deleted_devices` and
  `deleted_entities` lists are dropped: HA purges them on its own schedule,
  so they would churn without any configuration change.
- `.storage/core.config_entries` as a summary only
  (`core.config_entries.summary.json`: entry ID, domain, title, source,
  disabled state). The full file holds credentials and OAuth tokens.

Never captured: `secrets.yaml`, `.storage/auth*`, `.storage/onboarding`,
`.storage/core.config`, the recorder database, logs, `.cloud/`, `tts/`, `www/`,
`deps/`, and add-on configuration.

To capture more, add the path to `import-allowlist.toml` **and** a matching
re-include line to `.gitignore`. Open the file in a real backup first and
check what it holds.

## Setup

Python 3.11 or newer.

```sh
python3 -m venv .venv
.venv/bin/pip install -r scripts/requirements.txt
```

`securetar` is needed only for encrypted backups, which is what HA produces
when a backup encryption key is set.

## Importing a backup

1. In HA, download a backup from **Settings → System → Backups**. It must
   include Home Assistant (the core configuration). Keep it outside this
   repository.
2. Run the importer. It prompts for the backup encryption key without echoing
   it. The key is never accepted as a command-line argument.

   ```sh
   .venv/bin/python scripts/import-backup.py ~/Downloads/<backup>.tar
   ```

   To read the key from a password manager CLI instead of typing it, pipe it
   in with `--key-stdin`, for example with Bitwarden:

   ```sh
   bw get password "<vault item name>" | .venv/bin/python scripts/import-backup.py --key-stdin ~/Downloads/<backup>.tar
   ```

3. Run the audits (see [Audits](#audits)).
4. Review `git status` and `git diff`, then commit. Put the backup date and HA
   version (printed by the importer) in the commit message.

The importer builds the new tree in a temporary directory and replaces
`config/` only if the archive layout is recognized and the sensitive-value scan
passes. It never extracts archive members to disk by their archive paths.

### Sensitive-value scan

Captured files are scanned for:

- `webhook_id` values. A webhook ID is a bearer credential for anyone who can
  reach `/api/webhook/`. Fix it in HA by moving the ID to `!secret`, or run the
  importer with `--redact-webhook-ids` to replace each ID with a stable
  placeholder derived from a hash of the ID. A short, guessable ID can be
  recovered from its hash, so prefer long random IDs.
- Literal `token`, `api_key`, `password`, `client_secret`, and similar keys,
  and `Authorization: Bearer|Basic` headers, that are not `!secret` references
  or templates.
- URLs that carry their own credential: Discord, Slack, Teams, and Telegram
  webhook/bot URLs, `user:password@` URLs, and query strings with `token=`,
  `key=`, `sig=`, and similar. Move these to `!secret` in HA.
- Numeric `latitude` / `longitude` values.
- Literal lock and alarm codes (`code`, `pin`, `passcode`, `arm_code`, and
  similar keys) that are not `!secret` or templates.

Findings print as `file:line: kind`, without the value. The import fails if
any finding is unresolved.

### Always redacted

Personal identifiers with no audit value are replaced in every output file:

- Email addresses become `redacted-<hash>@redacted.invalid`. The hash is
  stable, so the same address still matches across files and imports.
- `serial_number` values and inline `s/n: …` / `serial: …` values become
  `REDACTED`.

MAC addresses and LAN IPs are kept on purpose: network inventory and IP
audits need them. This is one more reason to keep the repository private.

### gitleaks

`.gitleaks.toml` extends gitleaks' default rules with Discord webhook and
`user:password@` URL rules. It runs as a pre-commit hook and in CI
(`.github/workflows/gitleaks.yml`) over full history.

```sh
brew install pre-commit gitleaks   # or your platform's package manager
pre-commit install
gitleaks dir config --config .gitleaks.toml --redact --verbose
```

If the first `gitleaks dir` run flags registry IDs as generic secrets, add a
narrow `[[allowlists]]` entry for that rule and path rather than excluding the
file.

## Audits

Audit scripts read only `config/` and write Markdown reports to `reports/`.
Run them after each import and commit the reports with the snapshot, so a
report's diff shows what the import fixed or broke.

```sh
.venv/bin/python scripts/audit-dead-references.py
.venv/bin/python scripts/audit-orphans.py
```

- **Dead references** (`reports/dead-references.md`): entity, device, and
  area references in automations, scripts, scenes, templates, and dashboards
  that are missing from the registries or disabled there, and actions
  (`action:` / `service:` / `perform_action:`) that nothing provides: phone
  notify actions with no matching `mobile_app` device, scripts and
  `rest_command`s that do not exist, and domains with no loaded integration.
  `--check` exits 1 if any are found.
- **Orphans** (`reports/orphans.md`): the reverse. Registry entries whose
  YAML or `.storage` source is gone (deleted automations, scripts, and
  helpers; removed or commented-out YAML platforms; energy cost sensors
  whose metered entity was removed), helpers, scripts, and scenes nothing
  uses, disabled integrations, user-disabled entities and devices, and
  empty devices and areas. Cleanup candidates, not faults. `--check` exits 1
  if stale registry entries are found.

## Working with an agent

Point your agent at the repository and ask it to work from the reports, for
example: "Read `reports/orphans.md` and propose a PR removing helpers nothing
uses." Agents that read `AGENTS.md` (or `CLAUDE.md`) pick up the rules
automatically. Fill in `INSTANCE.md` so they know your conventions and
which findings are expected.

## Proposing changes

`config/` is a snapshot, not a deployment source. To propose a consolidation:

1. Edit the snapshot on a branch and open a PR that says what changes in HA
   behavior and how to verify it. Keep each PR small and of one kind.
2. The operator applies it in HA (automation editor YAML view, or the UI for
   helpers, areas, and entities).
3. Take a new backup, re-import, and confirm the diff matches the PR before
   merging.

## Updating from the template

A repository created with **Use this template** starts with a fresh history,
and a fork of a public repository cannot be private, so neither keeps you up
to date automatically. Instead, add the template as a second remote and merge
from it.

One-time setup, in your repository:

```sh
git remote add template https://github.com/<owner>/<template-repo>.git
git remote set-url --push template DISABLED   # never push your snapshot to it
git fetch template
git merge --allow-unrelated-histories template/main
```

The first merge joins the two histories. Resolve conflicts by taking the
template's version of template files (`scripts/`, `AGENTS.md`, `README.md`,
`.github/`, `.gitleaks.toml`) and keeping yours for `INSTANCE.md`,
`import-allowlist.toml`, `.gitignore` re-includes you added, `config/`, and
`reports/`.

After that, each update is an ordinary merge:

```sh
git fetch template
git merge template/main
```

Then re-run the importer and audits, since script changes can change the
output. Commit the regenerated `config/` and `reports/` separately from the
merge so the diff shows what the new scripts changed.

Keep customizations out of template files where you can (`INSTANCE.md` and
`import-allowlist.toml` exist for this), and merges stay conflict-free.
