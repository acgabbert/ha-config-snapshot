# Agent Operating Policy

Home Assistant is authoritative. This repository holds a normalized,
read-only snapshot of part of its configuration, imported from a backup with
secrets excluded. Agents work on the snapshot; the operator applies changes in
Home Assistant.

Read `INSTANCE.md` for facts about this particular installation.

## General

- Default to advising: give the user the commands and steps to run themselves.
- Do not connect to, inspect, or change Home Assistant or any other host,
  VM, container, service, network device, or cloud account.
- Never use SSH, stored credentials, API tokens, remote-management tools, or
  network access unless the user explicitly authorizes that specific action
  in the current request.
- A request to diagnose, plan, review, or explain is not authorization to
  execute operational commands.
- Before any privileged, destructive, or external action, show the exact
  command, target, and expected effect, then wait for explicit approval.
- Read-only repository inspection and explicitly requested edits within this
  repository are allowed. Keep all actions within the scope the user requested.

## Home Assistant specifics

- **No live access.** Do not use Home Assistant's MCP Server integration, the
  REST or WebSocket API, the Assist API, or the Supervisor API, even if a
  token is available. Work only on the files in `config/`.
- **`config/` is generated.** It is written by `scripts/import-backup.py` from a
  backup archive. Do not hand-edit it except on a branch that proposes a
  change for the operator to apply in Home Assistant (see README, "Proposing
  changes"). A re-import overwrites hand edits.
- **The allowlist is a review boundary.** Do not add paths, `.storage` files,
  or keys to `import-allowlist.toml`, or to the never-captured and summary
  rules in `scripts/import-backup.py`, without the user reviewing what the new
  path contains.
- **Never commit** backup archives, extracted trees, the backup encryption
  key, `secrets.yaml`, `.storage/auth*`, `.storage/core.config`, full
  `.storage/core.config_entries`, or the recorder database
  (`home-assistant_v2.db`).
- **Do not weaken the sensitive-value scan** to make an import pass. If the
  scan fails, report the file, line, and kind, and let the user decide whether
  to fix the source in Home Assistant.
- When citing a finding, give the file and line, not the secret value.
- **Template files vs. instance files.** `scripts/`, `AGENTS.md`, `README.md`,
  `.gitleaks.toml`, and `.github/` come from the upstream template and are
  updated by merging it (README, "Updating from the template"). Put
  installation-specific notes in `INSTANCE.md`, not in those files.
