# grok-intrupt-hook

A Grok Build CLI `PreToolUse` hook that gates high-risk tool calls behind a human approval. Before Grok executes a destructive shell command or writes/edits a file, it pauses, notifies your approver via Slack (or any intrupt channel), and waits. The tool only runs if a human clicks **Approve**.

```
Grok Build CLI
  │
  ├─ rm -rf /home/user          (matches AEGMIS_BLOCKED_PATHS)
  │     ⇒  ⛔ denied locally — no API call, no Slack
  │
  └─ kubectl delete pod nginx   (matches a risk pattern)
        │
        ▼
  PreToolUse hook fires
        │
        ▼
  POST /org/{id}/approval  ──►  intrupt API  ──►  Slack message
        │                                              │
        │  poll every 5s                     human clicks Approve / Reject
        │                                              │
        ▼                                              ▼
  GET /approval/{id}  ◄──────────────────────  status = "approved"
        │
        ▼
  exit 0  →  Grok continues
  exit 2  →  Grok is blocked (reason on stderr)
```

---

## Quick start

```bash
# 1. Install
curl -fsSL https://raw.githubusercontent.com/Aegmis/grok-intrupt-hook/main/install.sh | bash

# 2. Set your API key, then load the env
nano ~/.grok/.env.intrupt          # set AEGMIS_API_KEY=sk_org_...
source ~/.grok/.env.intrupt        # also add this line to ~/.zshrc or ~/.bashrc

# 3. Restart Grok CLI — done. High-risk actions now pause for Slack approval.
```

Installer defaults: **local mode**, **shell-only** gating, and deleting the home
dir itself routes to approval (`AEGMIS_PROTECTED_PATHS=re:^$HOME$`). To make a path
**impossible to delete** — denied instantly, never sent to a human — add it to
`AEGMIS_BLOCKED_PATHS` (e.g. `export AEGMIS_BLOCKED_PATHS=re:^$HOME$` in your env file).

---

## Prerequisites

- Grok Build CLI (hooks support; `~/.grok/user-settings.json`)
- Python 3.10+
- An [Aegmis](https://aegmis.com) account with an API key
- Slack workspace connected to your Aegmis org (for the default channel)

---

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Aegmis/grok-intrupt-hook/main/install.sh | bash
```

<details>
<summary>Prefer to clone first?</summary>

```bash
git clone https://github.com/Aegmis/grok-intrupt-hook.git
cd grok-intrupt-hook
bash install.sh
```

</details>

`install.sh`:

1. Copies `hook.py` to `~/.grok/hooks/intrupt_hook.py`
2. Merges the hook trigger into `~/.grok/user-settings.json`
3. Creates `~/.grok/.env.intrupt` with placeholder env vars

Then fill in your credentials and **restart Grok**:

```bash
nano ~/.grok/.env.intrupt
source ~/.grok/.env.intrupt   # add this to ~/.zshrc or ~/.bashrc too
```

---

## How it works

### 1. Grok fires the hook

Before Grok runs a tool, it passes a JSON payload to `hook.py` on stdin (the `PreToolUse` event):

```json
{
  "tool_name": "bash",
  "tool_input": { "command": "rm -rf /home/user" }
}
```

### 2. The hook decides whether to gate

Grok's exact tool-name vocabulary isn't fully documented, so the hook gates by the **shape** of `tool_input`:

- a **`command`** (or `cmd`/`script`) string → treated as a **shell command**
- a **file path** key (`file_path`/`path`/…) **plus** content (`content`/`new_str`/…) or an edit-like tool name → treated as a **file write/edit**
- anything else (reads, listings, searches) → **allowed** immediately

Shell commands are checked against a risk-pattern list in local mode (**catastrophic `rm`** targeting home/root/system dirs — routine & project-local deletes pass, `git push`, `sudo`, `terraform apply`, `curl … | sh`, etc.); file writes/edits are always gated. In **forward-all mode** (the default), every gated call is instead sent to the Aegmis policy engine.

> **Tuning:** if a gated action slips through, run it once and note the `tool_name` Grok used, then either tighten the `matcher` in `user-settings.json` or set `AEGMIS_GATED_TOOLS` to those exact names.

### 3. Approval is requested & polled

The hook POSTs to `/org/{org_id}/approval`, your Slack channel gets an interactive Approve/Reject message, and the hook polls `/approval/{id}` every 5 s.

| Outcome | Exit code | Grok |
|---|---|---|
| Human clicks **Approve** | `0` | Tool runs normally |
| Human clicks **Reject** | `2` | Tool blocked, reason (stderr) shown to Grok |
| Timeout (default 10 min) | `2` | Tool blocked with timeout message |
| API unreachable / hook crash | `2` | Tool blocked (fail closed) |

Grok's convention is **exit `2` = block** (reason read from stderr), **exit `0` = allow**. Any other exit code is a *non-blocking* error (fail-open) — so `hook.py` wraps its whole run and converts any unexpected failure into an explicit exit-2 block.

---

## What gets gated

Two tiers, evaluated in **local mode** (`AEGMIS_FORWARD_ALL=false`, the installer default):

**Hard-blocked — denied instantly, never sent to a human** (`AEGMIS_BLOCKED_PATHS`)

Only an `rm` whose target (resolved against the command's cwd, so relative paths
count) matches a `AEGMIS_BLOCKED_PATHS` entry. Denied locally with no approval
round-trip. Opt-in — nothing is hard-blocked unless you list it.

**Gated — paused for Slack approval**

The hook ships **20 built-in risk patterns**, identical across all 9 hooks. Several are families (one pattern, many commands), so they cover **30+ distinct dangerous commands**:

| Category | Matches | Passes through |
|---|---|---|
| Catastrophic `rm` | `rm -rf ~`, `rm -rf /`, `rm -rf /Users/you`, `rm *`, `rm -rf .` | `rm file.txt`, `rm -rf node_modules`, `rm -rf build` |
| Protected paths | `rm` of any dir in `AEGMIS_PROTECTED_PATHS` (default `re:^$HOME$`) + its subtree | anything not listed |
| Git | `git push` (incl. `--force`), `git reset --hard` | `git status`, `git commit`, `git pull` |
| Publish / release | `gh pr merge`, `gh release`, `npm publish`, `deploy` | builds, tests |
| Infra | `kubectl delete`/`apply`, `terraform apply`/`destroy` | `kubectl get`, `terraform plan` |
| Database | `DROP TABLE`, `TRUNCATE TABLE` | `SELECT`, `INSERT` |
| Disk | `dd if=`, `mkfs` | — |
| Privilege / perms | `sudo`, `chmod 777`, `chown … root` | `chmod 644` |
| Remote-to-shell | `curl … \| sh`, `wget -O- … \| sh` | plain `curl`/`wget` downloads |

Plus any **file write/edit** tool call is gated whenever that tool is in
`AEGMIS_GATED_TOOLS` — the installer default gates the **shell only**, so file
writes run free out of the box until you add them.

Everything else — reads, listings, `ls`, routine deletes — runs untouched. In
**forward-all mode** (`AEGMIS_FORWARD_ALL=true`) these local patterns are bypassed
and every gated tool call is sent to the **server-side policy engine** instead,
where your Aegmis policies decide — any command you write a policy for. The
`policies.example.sh` reference ships **~23 more** ready-to-use destructive-action
regexes (`find -delete`, `shred`, `docker push`, `crontab -r`, cloud-CLI deletes,
`kill`/`shutdown`, and more).

---

## Guarding your paths (approval vs hard-block)

Two env vars control what happens when the agent tries to `rm` a path you care
about. Both take a comma-separated list of **literal dirs** or **`re:`-prefixed
regexes**, resolved against the command's cwd (so relative targets like `./work`
are caught too).

| Variable | A matching `rm`… | Reach for it when |
|---|---|---|
| `AEGMIS_PROTECTED_PATHS` | pauses for **Slack approval** — a human can still allow it | the path matters but is *sometimes* legitimately deleted |
| `AEGMIS_BLOCKED_PATHS` | is **denied locally, instantly** — no Slack, nothing to approve | the path must **never** be deleted by the agent |

If a path matches **both**, the hard block wins — it's checked first, before any
approval round-trip. Both are **local-mode** features (`AEGMIS_FORWARD_ALL=false`,
the installer default).

### Minimal steps

1. Open your env file: `~/.grok/.env.intrupt`
2. Add either variable — one path or many, comma-separated:

   ```bash
   # Ask a human before deleting these  →  approval
   export AEGMIS_PROTECTED_PATHS="$HOME/work,$HOME/important"

   # Never let the agent delete these   →  hard block (no approval)
   export AEGMIS_BLOCKED_PATHS="re:^$HOME$,$HOME/.ssh"
   ```
3. Reload it: `source ~/.grok/.env.intrupt` (or restart Grok CLI).

### Examples

| Goal | Entry |
|---|---|
| Approve before wiping the home dir itself | `AEGMIS_PROTECTED_PATHS=re:^$HOME$` |
| Approve deletes of `work` + `important` (and their subtrees) | `AEGMIS_PROTECTED_PATHS=re:^$HOME/(work\|important)(/\|$)` |
| Hard-block `~/.ssh` and everything under it | `AEGMIS_BLOCKED_PATHS=$HOME/.ssh` |
| Hard-block the home dir itself (its contents still run free) | `AEGMIS_BLOCKED_PATHS=re:^$HOME$` |
| Mix — approve `work`, hard-block `~/.ssh` | `AEGMIS_PROTECTED_PATHS=$HOME/work` · `AEGMIS_BLOCKED_PATHS=$HOME/.ssh` |

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `AEGMIS_BASE_URL` | yes | — | intrupt API base URL |
| `AEGMIS_API_KEY` | yes | — | API key from Account → API Keys |
| `AEGMIS_APPROVAL` | no | `true` | Master kill switch — set `false` to disable the gate entirely (allow all) |
| `AEGMIS_GATED_TOOLS` | no | *(shape detection)* | If set, gate ONLY these exact tool names |
| `AEGMIS_FORWARD_ALL` | no | `true` | Forward every gated call to the policy engine (unmatched auto-approve) |
| `AEGMIS_TIMEOUT` | no | `600` | Max seconds to wait for a decision |
| `AEGMIS_POLL_INTERVAL` | no | `5` | Seconds between status polls |
| `AEGMIS_CHANNEL` | no | `slack` | Where the approval request is delivered — `slack` or `email` |
| `AEGMIS_BYPASS_PATTERNS` | no | — | Comma-separated regex; matching shell commands skip approval |
| `AEGMIS_PROTECTED_PATHS` | no | `re:^$HOME$` (set by installer) | Comma-separated dir(s) to also gate `rm` on — each dir **and everything under it**, cwd-resolved. List **one or many** (e.g. `~/work,~/secrets`). Prefix an entry with **`re:`** for a regex tested against the resolved absolute path, e.g. `re:^$HOME$` (home dir only) or `re:^$HOME/(work\|important)(/\|$)` |
| `AEGMIS_BLOCKED_PATHS` | no | — | Same syntax as `AEGMIS_PROTECTED_PATHS`, but an `rm` hitting one is **denied locally with no approval round-trip** — never sent to a human. Use for paths that must *never* be deleted. **Local mode only** (`AEGMIS_FORWARD_ALL=false`). |

**Approval channel:** requests go to **Slack** by default. To deliver them over **email** instead, set `AEGMIS_CHANNEL=email` in your env file.

> **Hook timeout:** the bundled `user-settings.json` sets `"timeout": 630` (seconds) so it exceeds `AEGMIS_TIMEOUT` (600 s). If you raise `AEGMIS_TIMEOUT`, raise the hook `timeout` to match.

---

## Grok settings

`install.sh` writes the following to `~/.grok/user-settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "bash|shell|exec|edit|write|create|str_replace|apply_patch|file",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.grok/hooks/intrupt_hook.py",
            "timeout": 630
          }
        ]
      }
    ]
  }
}
```

The `matcher` is a regex compared against `tool_name`. It's intentionally broad; the hook's shape detection does the precise filtering (and exits 0 quickly for non-gated calls).

---

## Example: catastrophic-deletion gate + protecting your own paths

In **local mode** (`AEGMIS_FORWARD_ALL=false`) the hook gates only *catastrophic*
deletions and lets routine ones run untouched:

```bash
rm abc.txt                 # runs   — routine single-file delete
rm -rf node_modules        # runs   — project-local
rm -rf ~                   # ⛔ approval — wipes home
rm -rf /                   # ⛔ approval — wipes root
rm *                       # ⛔ approval — bare glob
```

To also require approval before deleting **specific dirs of yours**, list them:

```bash
export AEGMIS_PROTECTED_PATHS=/Users/you/work,/Users/you/important
```

### `AEGMIS_PROTECTED_PATHS` — literal paths and `re:` regexes

Comma-separated entries — each a **literal** dir or a **`re:`**-prefixed **regex** (the regex is tested against the resolved absolute `rm` target):

| Entry | Effect |
|---|---|
| `re:^$HOME$` | gate `rm` of the **home dir itself only** — `rm -rf ~` gates, but `rm -rf ~/project` and `rm ~/notes.txt` run free *(installer default)* |
| `re:^$HOME/(work\|important)(/\|$)` | gate the `work` + `important` **subtrees** |
| `~/work,re:^$HOME$` | **mixed** — literal `work` subtree *and* regex home-exact both gate; anything else runs free |
| `~/work` | plain **literal** — that dir and everything under it |

Anchor a regex with `^…$` to match a dir exactly (not its contents). Invalid regexes are skipped with a stderr warning.

**Worked examples** (write these as `AEGMIS_PROTECTED_PATHS` entries; `$HOME` expands when the env file is sourced):

| Intent | Entry |
|---|---|
| Protect **only the home dir itself**, not its contents | `re:^$HOME$` |
| Protect `work` + `important` (and their subtrees) | `re:^$HOME/(work\|important)(/\|$)` |
| Protect `project/demo` **except** `project/demo/scratch` | `re:^$HOME/project/demo/(?!scratch(/\|$)).*` |
| Protect any `.env` / secrets file anywhere under home | `re:^$HOME/.*(\.env(\|\.)\|/secrets?/)` |
| Multiple, mixed with literal | `$HOME/work,re:^$HOME$` |


Targets are resolved against the command's working directory, so relative refs are
caught too:

```bash
# with AEGMIS_PROTECTED_PATHS=/Users/you/work
cd /Users/you && rm -rf ./work     # ⛔ approval  (./work → /Users/you/work)
rm -rf /Users/you/work/build       # ⛔ approval  (under a protected dir)
rm -rf /Users/you/other            # runs        — not protected
```

---

## Testing

```bash
python3 test_hook.py
```

Expected output:

```
[PASS] bash — git push (gated)
[PASS] bash — ls (allowed)
[PASS] bash — rm -rf ~ (catastrophic, gated)
[PASS] bash — git status (allowed)
[PASS] edit tool — file+content (gated)
[PASS] write_file — file+content (gated)
[PASS] view_file — read (allowed)
[PASS] bash — deploy (gated)
[PASS] bash — sudo apt (gated)
[PASS] bash — curl | sh (gated)

Results: 10/10 passed ✓
```

> These smoke tests validate the **gating logic** offline. Because Grok's exact
> tool-name/stdin schema is not fully published, do a one-time live check after
> install: ask Grok to `git push` and confirm you get a Slack approval.

---

## Security notes

- **Fails closed**: unreachable API, missing env vars, timeout, or a hook crash all block (exit 2).
- `AEGMIS_API_KEY` is a `Bearer` token — keep it in `.env.intrupt` with `600` permissions, not in shell history.

---

## Project structure

```
grok-intrupt-hook/
├── hook.py              # PreToolUse hook script (zero runtime dependencies)
├── test_hook.py         # Smoke tests for gating logic
├── install.sh           # One-line installer
├── user-settings.json   # Grok hooks config snippet
├── policies.example.sh  # Example Aegmis approval policies
├── .env.example         # Environment variable template
└── README.md
```

---

## Uninstalling

```bash
rm ~/.grok/hooks/intrupt_hook.py
```

Then remove the `PreToolUse` block from `~/.grok/user-settings.json`.
