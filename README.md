# grok-intrupt-hook

A Grok Build CLI `PreToolUse` hook that gates high-risk tool calls behind a human approval. Before Grok executes a destructive shell command or writes/edits a file, it pauses, notifies your approver via Slack (or any intrupt channel), and waits. The tool only runs if a human clicks **Approve**.

```
Grok Build CLI
  └─ wants to run: git push origin main
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
  "tool_input": { "command": "git push origin main" }
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
| `AEGMIS_BYPASS_PATTERNS` | no | — | Comma-separated regex; matching shell commands skip approval |
| `AEGMIS_PROTECTED_PATHS` | no | `re:^$HOME$` (set by installer) | Comma-separated dir(s) to also gate `rm` on — each dir **and everything under it**, cwd-resolved. List **one or many** (e.g. `~/work,~/secrets`). Prefix an entry with **`re:`** for a regex tested against the resolved absolute path, e.g. `re:^$HOME$` (home dir only) or `re:^$HOME/(work\|important)(/\|$)` |

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
