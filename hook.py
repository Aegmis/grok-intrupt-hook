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
             A crash is also converted to a blocking exit 2 so the gate fails
             CLOSED, never open.

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
                           NOTE: a few hard local gates (workspace wipe,
                           self-protection, and AEGMIS_BLOCKED_PATHS) always
                           apply, in BOTH modes.
  AEGMIS_TIMEOUT         Max seconds to wait for a decision. Default: 600 (10 min)
  AEGMIS_POLL_INTERVAL   Seconds between status polls. Default: 5
  AEGMIS_BYPASS_PATTERNS Comma-separated regex for shell commands that skip
                           approval (allow-list). Matched per command segment.
"""

import json
import os
import re
import shlex
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

_HOME = os.path.expanduser("~")

# Shell commands matching ANY of these patterns require approval (local mode).
# Keep patterns specific to reduce interruption noise. Evaluated per command
# SEGMENT (a chain like `a && b | c ; d` is split on && || ; & and newlines,
# pipelines stay intact) so a benign first command can't shield a risky one.
SHELL_GATE_PATTERNS: list[str] = [
    # Catastrophic deletions — home/root/system dirs or a bare */./..  (Project /
    # workspace wipes are handled separately by _rm_hits_workspace, which resolves
    # the target against cwd and so also catches ./ , "$PWD", quoted "$HOME", etc.)
    r"\brm\b[\s\S]*\s(~/?(\s|$)|\$\{?HOME\}?/?(\s|$)|/(\s|$)|/\*|/(Users|home)/[^/\s]+/?(\s|$)|/(etc|usr|var|bin|sbin|opt|System|Library|private|boot|dev|lib|sys|proc)(/|\s|$)|\*(\s|$)|\.(\s|$)|\.\.(/|\s|$))",
    # ── Destructive / mass deletes beyond plain rm ─────────────────────────────
    r"\bfind\b[\s\S]*\s-delete\b",
    r"\bfind\b[\s\S]*-exec\s+rm\b",
    r"\bgit\s+clean\s+-[a-z]*f",         # git clean -f / -fd / -fdx
    r"\brsync\b[\s\S]*--delete\b",
    r"\bshred\b",
    r"\bunlink\b\s",
    # ── History / repo rewrites ────────────────────────────────────────────────
    r"\bgit\s+reset\s+--hard\b",
    r"\bgit\s+(rebase|filter-branch|filter-repo)\b",
    r"\bgit\s+branch\s+-D\b",
    # ── Code / data egress (exfiltration) ──────────────────────────────────────
    r"\bgit\s+push\b",                   # any git push (including --force)
    r"\bgit\s+remote\s+(add|set-url)\b", # re-point a remote (then push elsewhere)
    r"\bgh\s+repo\s+create\b",           # can publish a repo (--public --push)
    r"\bgh\s+repo\s+edit\b[\s\S]*--visibility",
    r"\bgh\s+gist\s+create\b",           # public gist = code leak
    r"\bgh\s+pr\s+merge\b",
    r"\bgh\s+release\b",
    r"\bcurl\b[\s\S]*(\s-T\b|--upload-file\b|\s-F\b|--form\b|--data-binary\s*@|\s-d\s*@|--data\s*@)",
    r"\bwget\b[\s\S]*--post-file\b",
    r"\bscp\b\s",                        # copy off-box
    r"\brsync\b[\s\S]*\s[^\s]+@[^\s:]+:", # rsync to user@host:
    r"\b(nc|ncat|netcat)\b\s",           # netcat pipe-out
    # ── Publish / release / deploy ─────────────────────────────────────────────
    r"\bnpm\s+publish\b",
    r"\b(pip|twine)\s+upload\b|\btwine\s+upload\b",
    r"\b(cargo\s+publish|gem\s+push|poetry\s+publish)\b",
    r"\bdocker\s+(push|login)\b",
    r"\bdeploy\b",
    r"\bkubectl\s+delete\b",
    r"\bkubectl\s+apply\b",
    r"\bterraform\s+apply\b",
    r"\bterraform\s+destroy\b",
    # ── Database ───────────────────────────────────────────────────────────────
    r"DROP\s+(TABLE|DATABASE|SCHEMA)",
    r"TRUNCATE\s+TABLE",
    # ── Disk / device ──────────────────────────────────────────────────────────
    r"\bdd\s+if=",
    r"\b(mkfs|wipefs|fdisk)\b",
    r">\s*/dev/(sd|nvme|disk|hd)",
    # ── Privilege / perms ──────────────────────────────────────────────────────
    r"\bsudo\b",
    r"\bchmod\s+[0-7]*7[0-7][0-7]\b",    # world-writable
    r"\bchown\b.*root",
    # ── Remote-to-shell & obfuscation (denylists can't see through these; gate) ─
    r"\|\s*(ba|z|k)?sh\b",               # ANY pipe to a shell (curl|sh, echo|sh…)
    r"\bbase64\b[\s\S]*(-d|-D|--decode)\b",  # decode-then-run smell
    r"\beval\b",
    r"\b(ba|z|k)?sh\s+-c\b",             # sh -c "…" wrapper
    r"\bxargs\b[\s\S]*\brm\b",
    r"\bpython[0-9.]*\b[\s\S]*-c\b[\s\S]*(rmtree|os\.remove|os\.unlink|shutil)",
    r"\bperl\b[\s\S]*-e\b[\s\S]*unlink",
]

# User-defined protected paths (AEGMIS_PROTECTED_PATHS) — literal entries also get
# a raw-command fallback pattern (regex entries are handled by _PROTECTED_REGEX).
for _pp in os.environ.get("AEGMIS_PROTECTED_PATHS", "").split(","):
    _pp = _pp.strip()
    if _pp and not _pp.startswith("re:"):   # literal entry -> raw-command fallback pattern
        SHELL_GATE_PATTERNS.append(r"\brm\b[\s\S]*\s" + re.escape(_pp.rstrip("/")) + r"(/|\s|$)")

_COMPILED = [re.compile(p, re.IGNORECASE) for p in SHELL_GATE_PATTERNS]

# Statement separators for chained commands. We DON'T split on a single pipe so
# that pipe-to-shell patterns (curl … | sh) stay inside one segment.
_SEG_SPLIT = re.compile(r"&&|\|\||;|&(?!&)|\n")

_STATE = {"cwd": ""}

# Protected paths (AEGMIS_PROTECTED_PATHS) resolved for cwd-aware matching.
# Each entry is a LITERAL dir (dir + subtree) or, when prefixed "re:", a REGEX
# tested against the resolved absolute rm target.
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

# Hard-blocked paths (AEGMIS_BLOCKED_PATHS) — same syntax; an `rm` hitting one is
# DENIED locally with no approval round-trip (both modes).
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

# Self-protection: the gate must not let the agent quietly disarm it. Writes,
# deletes, or edits touching these paths are always gated, regardless of
# AEGMIS_GATED_TOOLS. (Real containment is the OS sandbox — see README — but this
# closes the obvious "edit settings.json / .env.intrupt / hook.py" hole.)
_SELF_PROTECT = [
    os.path.normpath(os.path.join(_HOME, ".grok")),
]
# Extra self-protect basenames matched anywhere (project-local .grok, git hooks).
_SELF_PROTECT_SUFFIX = (
    os.path.join(".grok", ""),     # any .grok/ dir
    os.path.join(".git", "hooks"),
)
_MUTATING_VERB = re.compile(
    r"\b(rm|mv|cp|tee|truncate|dd|chmod|chown|ln|install|touch)\b|\bsed\s+-i|>\s*\S|>>\s*\S"
)


def _tokenize(command: str) -> list[str]:
    """Shell-aware token split (handles quotes); falls back to whitespace split."""
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _expand(path: str, cwd: str) -> str:
    """Expand ~, $HOME/${HOME}, $PWD/${PWD} the way the shell would."""
    p = path
    for var in ("${PWD}", "$PWD"):
        p = p.replace(var, cwd or ".")
    for var in ("${HOME}", "$HOME"):
        p = p.replace(var, _HOME)
    return os.path.expanduser(p)


def _resolve(path: str, cwd: str) -> str:
    """Resolve a path token to a normalized absolute path against cwd."""
    p = _expand(path, cwd)
    if not os.path.isabs(p):
        p = os.path.join(cwd or ".", p)
    return os.path.normpath(p).rstrip("/") or "/"


def _path_tokens(command: str) -> list[str]:
    """Candidate path tokens from a command (skip flags/verbs/redirection ops)."""
    out = []
    for tok in _tokenize(command):
        t = tok.lstrip("<>&|")           # strip redirection glyphs (>file, 2>&1…)
        t = t.strip("'\"")
        if not t or t.startswith("-") or t in ("rm", "sudo", "--", "mv", "cp",
                                               "tee", "sed", "ln", "chmod", "chown",
                                               "install", "touch", "cat", "&&", "||", ";", "|"):
            continue
        out.append(t)
    return out


# ── Path-based gates ───────────────────────────────────────────────────────────

def _rm_hits(command: str, literals: list, regexes: list) -> bool:
    """True if an rm target (resolved against cwd) matches a literal path
    (dir + subtree) or a `re:` regex (against the resolved absolute path)."""
    if (not literals and not regexes) or not re.search(r"\brm\b", command):
        return False
    for t in _path_tokens(command):
        cand = _resolve(t, _STATE["cwd"])
        for prot in literals:
            if cand == prot or cand.startswith(prot + "/"):
                return True
        for _rx in regexes:
            if _rx.search(cand):
                return True
    return False


def _rm_hits_protected(command: str) -> bool:
    return _rm_hits(command, _PROTECTED_LITERAL, _PROTECTED_REGEX)


def _rm_hits_blocked(command: str) -> bool:
    return _rm_hits(command, _BLOCKED_LITERAL, _BLOCKED_REGEX)


# Write/create gate for AEGMIS_PROTECTED_PATHS — gate not just `rm` of a protected
# path but also file CREATION / writes INTO it (touch, tee, cp/mv, `>`/`>>`
# redirection). Scoped to protected dirs only, so writes elsewhere stay free.
# Mirrors the rm-based protected-path gate.
_WRITE_VERB = re.compile(r"\b(touch|tee|cp|mv|install|dd|ln)\b|>\s*\S|>>\s*\S")


def _write_hits(command: str, literals: list, regexes: list) -> bool:
    """True if a write/create verb targets a path under a literal dir (+subtree)
    or a `re:` regex."""
    if (not literals and not regexes) or not _WRITE_VERB.search(command):
        return False
    for t in _path_tokens(command):
        cand = _resolve(t, _STATE["cwd"])
        for prot in literals:
            if cand == prot or cand.startswith(prot + "/"):
                return True
        for _rx in regexes:
            if _rx.search(cand):
                return True
    return False


def _write_hits_protected(command: str) -> bool:
    return _write_hits(command, _PROTECTED_LITERAL, _PROTECTED_REGEX)


def _rm_hits_workspace(command: str) -> bool:
    """True if a delete targets the whole project — the working dir itself or any
    ancestor of it (or filesystem root). Deleting a SUBDIR (rm -rf build) stays
    free; wiping the project (rm -rf . / ./ / "$PWD" / .. / the cwd path) gates."""
    cwd = _STATE["cwd"]
    if not cwd:
        return False
    if not re.search(r"\b(rm|find)\b", command):
        return False
    cwd_n = os.path.normpath(cwd).rstrip("/") or "/"
    for t in _path_tokens(command):
        cand = _resolve(t, cwd)
        if cand == "/" or cand == cwd_n or cwd_n.startswith(cand + "/"):
            return True
    return False


def _hits_self_protect(command: str) -> bool:
    """True if a mutating shell command touches the hook's own config/dirs."""
    if not _MUTATING_VERB.search(command):
        return False
    for t in _path_tokens(command):
        cand = _resolve(t, _STATE["cwd"])
        if _path_under_self_protect(cand):
            return True
    return False


def _path_under_self_protect(cand: str) -> bool:
    for prot in _SELF_PROTECT:
        if cand == prot or cand.startswith(prot + "/"):
            return True
    norm = cand.replace("\\", "/")
    for suffix in _SELF_PROTECT_SUFFIX:
        s = suffix.replace("\\", "/").rstrip("/")
        if norm == s or ("/" + s + "/") in (norm + "/") or norm.endswith("/" + s):
            return True
    return False


# Optional allow-list: patterns whose matching Bash command segments bypass approval
_BYPASS_RAW = os.environ.get("AEGMIS_BYPASS_PATTERNS", "")
_BYPASS = [re.compile(p, re.IGNORECASE) for p in _BYPASS_RAW.split(",") if p.strip()]


def _segments(command: str) -> list[str]:
    segs = [s.strip() for s in _SEG_SPLIT.split(command) if s.strip()]
    return segs or [command]


def _segment_bypassed(seg: str) -> bool:
    return any(b.search(seg) for b in _BYPASS)


def _fully_bypassed(command: str) -> bool:
    """True only if EVERY segment matches a bypass pattern (so a benign segment
    can't waive a chained risky one)."""
    if not _BYPASS:
        return False
    return all(_segment_bypassed(s) for s in _segments(command))


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_org_id(api_key: str) -> str:
    """Extract org_id from API key format: sk_org_{org_id}_{hash}."""
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
    """Minimal HTTP client using only stdlib — no dependencies required."""
    url  = f"{BASE_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {API_KEY}",
            # Cloudflare returns HTTP 403 "error code: 1010" for the default
            # Python-urllib User-Agent (banned browser signature). Send a real one.
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
    """Deny the tool call — write reason to stderr and exit 2 (Grok's block signal).
    (exit 1 / any other non-zero would be a NON-blocking error — the tool would
    run — so we never use it.)"""
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


def _hard_local_gate(command: str) -> tuple[bool, str]:
    """Local gates that ALWAYS apply, in both forward-all and local mode:
    hard-blocked paths (denied outright), workspace wipes, and self-protection.
    Returns (should_ask_for_approval, reason); may _block() directly for deny."""
    if _rm_hits_blocked(command):
        _block("Deletion of a hard-blocked path is denied "
               "(AEGMIS_BLOCKED_PATHS) — not sent for approval.")
    if _rm_hits_workspace(command):
        return True, "workspace-wipe"
    if _hits_self_protect(command):
        return True, "self-protection (hook config)"
    return False, ""


def _should_gate_shell(command: str) -> tuple[bool, str]:
    """Local-mode risk decision, evaluated per command segment so a benign
    segment can't shield a risky one. Returns (gate, matched_reason)."""
    for seg in _segments(command):
        if _segment_bypassed(seg):
            continue
        if _rm_hits_protected(seg):
            return True, "protected-path"
        if _write_hits_protected(seg):
            return True, "protected-path (write)"
        for pattern in _COMPILED:
            if pattern.search(seg):
                return True, pattern.pattern
    return False, ""


def _classify(tool_name: str, tool_input: dict) -> tuple[str, dict]:
    """
    Decide what KIND of action this is: "shell", "file", "other", or "skip".
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

    # Self-protection: a write/edit whose target path is under the hook's own
    # config dir is ALWAYS gated, even if the tool isn't gated / classification
    # would skip it (closes the "edit ~/.grok/user-settings.json" disarm hole).
    sp_path = _first(tool_input, _PATH_KEYS)
    force_gate = bool(sp_path) and _path_under_self_protect(_resolve(sp_path, _STATE["cwd"]))

    if kind in ("skip", "other") and not force_gate:
        _allow()

    if kind == "shell":
        command = extra["command"]
        # Hard local gates apply in BOTH modes (deny / always-ask).
        hard, _hard_reason = _hard_local_gate(command)
        if not hard:
            if FORWARD_ALL:
                # Forward everything to the policy engine, but let a FULLY
                # bypassed command short-circuit to avoid a network round-trip.
                if _fully_bypassed(command):
                    _allow()
            else:
                gate, _matched = _should_gate_shell(command)
                if not gate:
                    _allow()  # low-risk command — allow locally
        action  = "bash_command"
        message = f"Run: `{command.splitlines()[0][:120] if command else ''}`"
    else:  # file (or a self-protect-forced write/edit)
        action  = "edit_file"
        path = (extra.get("path") if kind == "file" else None) or sp_path or "unknown"
        message = f"Edit file: `{path}`"

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
