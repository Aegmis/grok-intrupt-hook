#!/usr/bin/env python3
"""
Grok Build CLI PreToolUse hook — intrupt approval gate.

Reads a tool-call payload from stdin, POSTs to the intrupt API to create a
pending approval (which notifies the approver via Slack), then polls until a
human decides.

Grok hook contract (PreToolUse):
  - Registered in ~/.grok/user-settings.json under hooks.PreToolUse.
  - stdin  : JSON with tool_name and tool_input (event details).
  - Block  : exit code 2, with the reason written to stderr (Grok surfaces
             stderr to the agent). Exit 0 = allow. Any OTHER exit code is a
             non-blocking error (fail OPEN), so this hook only ever exits 0 or 2.

Because Grok's exact tool-name vocabulary is not fully documented, gating is
decided by the SHAPE of tool_input rather than exact tool names:
  - a "command" (or "cmd") string  → treated as a shell command
  - a file path key + content/new-text → treated as a file write/edit
This is robust across tool-name changes. Override with AEGMIS_GATED_TOOLS to
force gating on exact tool names instead.

Environment variables (required):
  AEGMIS_BASE_URL   Base URL of the intrupt approval API (e.g. https://api.aegmis.com)
  AEGMIS_API_KEY    API key from Account → API Keys (org ID is extracted automatically)

Optional:
  AEGMIS_GATED_TOOLS     Comma-separated exact tool names to gate. If set, ONLY
                           these tool names are considered (shape detection off).
  AEGMIS_FORWARD_ALL     If true (default), forward every gated call to the
                           policy engine (unmatched auto-approve). If false, use
                           the local SHELL_GATE_PATTERNS pre-filter for shell.
  AEGMIS_TIMEOUT         Max seconds to wait for a decision. Default: 600 (10 min)
  AEGMIS_POLL_INTERVAL   Seconds between status polls. Default: 5
  AEGMIS_BYPASS_PATTERNS Comma-separated regex for shell commands that skip
                           approval (allow-list). Applied in both modes.
"""

import json
import os
import re
import sys
import time
import uuid
import urllib.request
import urllib.error
from typing import Optional

# ── Configuration ─────────────────────────────────────────────────────────────

BASE_URL       = os.environ.get("AEGMIS_BASE_URL", "https://api.aegmis.com").rstrip("/")
API_KEY        = os.environ.get("AEGMIS_API_KEY", "")
TIMEOUT        = int(os.environ.get("AEGMIS_TIMEOUT", "600"))
POLL_INTERVAL  = int(os.environ.get("AEGMIS_POLL_INTERVAL", "5"))
# Approval delivery channel: "slack" (default) or "email".
CHANNEL        = os.environ.get("AEGMIS_CHANNEL", "slack")
FORWARD_ALL    = os.environ.get("AEGMIS_FORWARD_ALL", "true").lower() in ("1", "true", "yes")

# Kill switch: AEGMIS_APPROVAL=false disables the gate entirely (allow all).
APPROVAL_ENABLED = os.environ.get("AEGMIS_APPROVAL", "true").lower() not in ("0", "false", "no", "off", "disable", "disabled")

# Optional exact tool-name allow-list. When set, shape detection is disabled and
# only these tool names are gated.
_GATED_RAW = os.environ.get("AEGMIS_GATED_TOOLS", "")
GATED_TOOLS = {t.strip() for t in _GATED_RAW.split(",") if t.strip()}

# Keys that, when present in tool_input, identify a shell command / a file path.
_COMMAND_KEYS = ("command", "cmd", "script")
_PATH_KEYS    = ("file_path", "path", "filename", "file", "target_file")
_CONTENT_KEYS = ("content", "new_str", "new_string", "new_text", "contents", "patch")

# Shell commands matching ANY of these patterns require approval (local mode).
SHELL_GATE_PATTERNS: list[str] = [
    # Catastrophic deletions only — home/root/system dirs or a bare */./..  Routine
    # and project-local deletes (rm file, rm -rf node_modules/build) pass through.
    r"\brm\b[\s\S]*\s(~/?(\s|$)|\$\{?HOME\}?/?(\s|$)|/(\s|$)|/\*|/(Users|home)/[^/\s]+/?(\s|$)|/(etc|usr|var|bin|sbin|opt|System|Library|private|boot|dev|lib|sys|proc)(/|\s|$)|\*(\s|$)|\.(\s|$)|\.\.(/|\s|$))",
    r"\bgit\s+push\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bgh\s+pr\s+merge\b",
    r"\bgh\s+release\b",
    r"\bnpm\s+publish\b",
    r"\bdeploy\b",
    r"\bkubectl\s+delete\b",
    r"\bkubectl\s+apply\b",
    r"\bterraform\s+apply\b",
    r"\bterraform\s+destroy\b",
    r"DROP\s+TABLE",
    r"TRUNCATE\s+TABLE",
    r"\bdd\s+if=",
    r"\bmkfs\b",
    r"\bsudo\b",
    r"\bchmod\s+[0-7]*7[0-7][0-7]\b",
    r"\bchown\b.*root",
    r"\bcurl\b.*\|\s*(ba)?sh\b",
    r"\bwget\b.*-O\s*-\b.*\|\s*(ba)?sh\b",
]
# User-defined protected paths (AEGMIS_PROTECTED_PATHS) — also gate `rm` of each
# listed path and anything under it, on top of the built-in catastrophic targets.
for _pp in os.environ.get("AEGMIS_PROTECTED_PATHS", "").split(","):
    _pp = _pp.strip()
    if _pp and not _pp.startswith("re:"):   # literal entry -> raw-command fallback pattern
        SHELL_GATE_PATTERNS.append(r"\brm\b[\s\S]*\s" + re.escape(_pp.rstrip("/")) + r"(/|\s|$)")

_COMPILED = [re.compile(p, re.IGNORECASE) for p in SHELL_GATE_PATTERNS]

# Protected paths (AEGMIS_PROTECTED_PATHS) resolved for cwd-aware matching — this
# catches relative rm targets (./ok, ok, ../x) that literal patterns would miss.
_STATE = {"cwd": ""}
# Each AEGMIS_PROTECTED_PATHS entry is a LITERAL dir (dir + everything under it) or,
# when prefixed "re:", a REGEX tested against the resolved absolute rm target (anchor
# with ^...$ to match a dir exactly; alternation / lookahead supported).
_PROTECTED_LITERAL = []
_PROTECTED_REGEX = []
for _pp in os.environ.get("AEGMIS_PROTECTED_PATHS", "").split(","):
    _pp = _pp.strip()
    if not _pp:
        continue
    if _pp.startswith("re:"):
        try:
            _PROTECTED_REGEX.append(re.compile(_pp[3:]))
        except re.error as _exc:
            print(f"[intrupt hook] ignoring invalid AEGMIS_PROTECTED_PATHS regex {_pp[3:]!r}: {_exc}",
                  file=sys.stderr)
    else:
        _PROTECTED_LITERAL.append(os.path.normpath(os.path.expanduser(_pp.rstrip("/"))))

# Hard-blocked paths (AEGMIS_BLOCKED_PATHS) — same syntax as AEGMIS_PROTECTED_PATHS
# (literal dir + subtree, or "re:" regex), but an `rm` hitting one is DENIED locally
# with no approval round-trip. Local mode only (mirrors the protected-path gate).
_BLOCKED_LITERAL = []
_BLOCKED_REGEX = []
for _pp in os.environ.get("AEGMIS_BLOCKED_PATHS", "").split(","):
    _pp = _pp.strip()
    if not _pp:
        continue
    if _pp.startswith("re:"):
        try:
            _BLOCKED_REGEX.append(re.compile(_pp[3:]))
        except re.error as _exc:
            print(f"[intrupt hook] ignoring invalid AEGMIS_BLOCKED_PATHS regex {_pp[3:]!r}: {_exc}",
                  file=sys.stderr)
    else:
        _BLOCKED_LITERAL.append(os.path.normpath(os.path.expanduser(_pp.rstrip("/"))))


def _rm_hits(command: str, literals: list, regexes: list) -> bool:
    """True if an rm target (resolved against cwd) matches a literal path
    (dir + subtree) or a `re:` regex (against the resolved absolute path)."""
    if (not literals and not regexes) or not re.search(r"\brm\b", command):
        return False
    for tok in command.split():
        t = tok.strip("'\"")
        if not t or t in ("rm", "sudo", "--") or t.startswith("-"):
            continue
        t = os.path.expanduser(t)
        cand = t if os.path.isabs(t) else os.path.normpath(os.path.join(_STATE["cwd"] or ".", t))
        cand = os.path.normpath(cand).rstrip("/")
        for prot in literals:
            if cand == prot or cand.startswith(prot + "/"):
                return True
        for _rx in regexes:
            if _rx.search(cand):
                return True
    return False


def _rm_hits_protected(command: str) -> bool:
    """True if an rm target matches a protected literal path or `re:` regex."""
    return _rm_hits(command, _PROTECTED_LITERAL, _PROTECTED_REGEX)


def _rm_hits_blocked(command: str) -> bool:
    """True if an rm target matches a hard-blocked literal path or `re:` regex."""
    return _rm_hits(command, _BLOCKED_LITERAL, _BLOCKED_REGEX)


_BYPASS_RAW = os.environ.get("AEGMIS_BYPASS_PATTERNS", "")
_BYPASS = [re.compile(p, re.IGNORECASE) for p in _BYPASS_RAW.split(",") if p.strip()]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_org_id(api_key: str) -> str:
    if not api_key.startswith("sk_org_"):
        _die("Invalid AEGMIS_API_KEY format — expected 'sk_org_{org_id}_{hash}'")
    after_prefix = api_key[7:]
    last_underscore = after_prefix.rfind("_")
    if last_underscore == -1:
        _die("Invalid AEGMIS_API_KEY format — expected 'sk_org_{org_id}_{hash}'")
    org_id = after_prefix[:last_underscore]
    if not org_id.startswith("org_"):
        _die(f"Could not extract org ID from API key — got '{org_id}'")
    return org_id


def _api(method: str, path: str, body: Optional[dict] = None) -> dict:
    url  = f"{BASE_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {API_KEY}",
            "User-Agent":    "intrupt-hook/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        _die(f"intrupt API {method} {path} → HTTP {exc.code}: {body_text}")
    except urllib.error.URLError as exc:
        _die(f"intrupt API unreachable ({exc.reason}). Is AEGMIS_BASE_URL correct?")


def _allow() -> None:
    """Allow the tool call — exit 0 with no output."""
    sys.exit(0)


def _block(reason: str) -> None:
    """Deny the tool call — write reason to stderr and exit 2 (Grok's block signal)."""
    print(reason, file=sys.stderr, flush=True)
    sys.exit(2)


def _die(msg: str) -> None:
    """Fatal error — deny the tool call and report why (fail closed)."""
    _block(f"[intrupt hook error] {msg}")


def _first(d: dict, keys) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _bypassed(command: str) -> bool:
    return any(b.search(command) for b in _BYPASS)


def _should_gate_shell(command: str) -> bool:
    if _bypassed(command):
        return False
    if _rm_hits_protected(command):
        return True
    return any(p.search(command) for p in _COMPILED)


def _classify(tool_name: str, tool_input: dict) -> tuple[str, dict]:
    """
    Decide what KIND of action this is: "shell", "file", or "other".
    Returns (kind, extra) where extra carries the command or path.
    """
    # If an explicit tool-name allow-list is configured, honor it strictly.
    if GATED_TOOLS and tool_name not in GATED_TOOLS:
        return "skip", {}

    command = _first(tool_input, _COMMAND_KEYS)
    if command is not None:
        return "shell", {"command": command}

    path = _first(tool_input, _PATH_KEYS)
    has_content = any(k in tool_input for k in _CONTENT_KEYS)
    looks_like_edit = bool(re.search(r"edit|write|create|replace|patch|append|insert", tool_name, re.I))
    if path is not None and (has_content or looks_like_edit):
        return "file", {"path": path}

    # Tool-name explicitly allow-listed but shape unknown → gate defensively.
    if GATED_TOOLS and tool_name in GATED_TOOLS:
        return "file", {"path": path or "unknown"}

    return "other", {}


# ── Main ────────────────────────────────────────────────────────────────────────

def main() -> None:
    raw = sys.stdin.read()
    if not APPROVAL_ENABLED:
        _allow()  # AEGMIS_APPROVAL disabled — allow without gating
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        _die("Could not parse hook payload from stdin")

    _STATE["cwd"] = payload.get("cwd") or payload.get("working_dir") or ""

    tool_name  = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            tool_input = {"raw": tool_input}
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}

    kind, extra = _classify(tool_name, tool_input)

    if kind in ("skip", "other"):
        _allow()

    if kind == "shell":
        command = extra["command"]
        if FORWARD_ALL:
            if _bypassed(command):
                _allow()
        else:
            if _rm_hits_blocked(command):
                _block("Deletion of a hard-blocked path is denied "
                       "(AEGMIS_BLOCKED_PATHS) — not sent for approval.")
            if not _should_gate_shell(command):
                _allow()
        action  = "bash_command"
        message = f"Run: `{command.splitlines()[0][:120] if command else ''}`"
    else:  # file
        action  = "edit_file"
        message = f"Edit file: `{extra.get('path', 'unknown')}`"

    if not API_KEY:
        _die("AEGMIS_API_KEY is not set")
    org_id = _extract_org_id(API_KEY)

    thread_id = str(uuid.uuid4())

    resp = _api("POST", f"/org/{org_id}/approval", {
        "thread_id":   thread_id,
        "action":      action,
        "message":     message,
        "channel":     CHANNEL,
        "tool_name":   tool_name,
        "tool_kwargs": tool_input,
        "adapter":     "grok",
    })

    status = resp.get("status", "pending")
    if status == "approved":
        _allow()
    if status in ("rejected", "denied"):
        _block(f"Approval rejected (status={status})")

    approval_id = resp.get("approval_id") or resp.get("audit_id")
    if not approval_id:
        _die(f"API did not return approval_id/audit_id: {resp}")

    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        status_resp = _api("GET", f"/org/{org_id}/approval/{approval_id}")
        status = status_resp.get("status", "pending")
        if status == "approved":
            _allow()
        if status in ("rejected", "denied"):
            _block(f"Approval rejected by approver (approval_id={approval_id})")

    _block(
        f"Approval timed out after {TIMEOUT}s — tool call blocked "
        f"(approval_id={approval_id}). Approve or reject it in the dashboard."
    )


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 — fail closed on ANY crash
        # Grok treats a non-2 exit as a non-blocking error (fail OPEN), so
        # convert any unexpected failure into an explicit exit-2 block.
        _block(f"[intrupt hook error] unexpected failure: {exc!r}")
