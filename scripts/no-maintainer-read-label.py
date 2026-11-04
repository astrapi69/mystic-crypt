#!/usr/bin/env python3
"""PreToolUse hook: no Claude Code session sets or removes the label read-by-maintainer (#737).

A pull request that changes a path .github/CODEOWNERS lists keeps the status maintainer-read red until the
maintainer has set the label read-by-maintainer himself, after reading every changed line (#732). Every agent acts as
the GitHub account astrapi69, so GitHub cannot tell his label from an agent's; this hook is the part that can, for a
session of Claude Code. .claude/settings.json runs it for every session started in the repository, local or in the
cloud, and the maintainer's own ~/.claude/settings.json runs the same file on his machine.

Refused is a tool call that writes the label:
- a Bash command with a line that writes to GitHub (gh pr|issue edit|create, gh api with a method, fields or input,
  a GraphQL label mutation) together with a way of setting a label (--add-label, --remove-label, --label, -l, the
  labels endpoints, a labels field), when the label's name is in the command, in a script it runs or in a file it
  hands over; the same for every line of a script the command runs;
- a GitHub MCP tool that is not a read (get, list, search, read, view, query, fetch) and whose input names the label.
Reading the label, in an API response, a JSON fixture, a grep or a text that describes it, is allowed.

The known limit of the smallest form (#732, option a): the hook holds back only what runs through Claude Code. A
direct call to the GitHub API with curl and a token, a program the hook cannot see into, or the browser can still set
the label; whoever holds the account's credentials can. It turns an accident into a refusal; it is not access control.

Self-test: python3 -I scripts/no-maintainer-read-label.py --self-test
"""
import json
import re
import sys
from datetime import datetime
from pathlib import Path

LABEL = "read-by-maintainer"
# The GraphQL mutation names are written in two pieces, so that this file does not read as a line that writes and
# sets the label when the hook reads it as a script a command runs.
MUTATIONS = r"|add" r"LabelsToLabelable|remove" r"LabelsFromLabelable"
SETTING = re.compile(r"--add-label\b|--remove-label\b|--label\b|(?:^|\s)-l\s|/labels\b|\blabels\s*(?:\[\]|=|\"\s*:)"
                     + MUTATIONS)
GH_WRITE = re.compile(r"\bgh\s+(?:pr|issue)\s+(?:edit|create)\b"
                      r"|\bgh\s+api\b[^\n]*(?:\s-X\s*(?:POST|PUT|PATCH|DELETE)|--method\s+(?:POST|PUT|PATCH|DELETE)"
                      r"|\s-[fF]\s|--(?:raw-)?field\b|--input\b|\sgraphql\b)"
                      + MUTATIONS)
# a script the command runs: after an interpreter, source or ".", or as a command of its own; a script the command
# only reads, shows or copies is not run
EXECUTED = re.compile(r"(?:^|[;&|(]\s*|\b(?:bash|sh|zsh|python3?|source|exec)\s+(?:-\S+\s+)*|(?:^|\s)\.\s+)"
                      r"([~\w./-]+\.(?:sh|bash|zsh|py))\b", re.MULTILINE)
INPUT = re.compile(r"[~\w./-]+\.(?:json|md|txt|sh|bash|zsh|py)\b")
MCP_GITHUB = re.compile(r"^mcp__[^_]*github[^_]*__(?P<tool>.+)$", re.IGNORECASE)
MCP_READ = re.compile(r"(?:^|_)(?:get|list|search|read|view|query|fetch)(?:_|$)", re.IGNORECASE)
LOG = Path.home() / ".claude/hooks/no_maintainer_read_label.log"


def read(token):
    """The text of an existing file a command names, or None; this hook's own file is never read."""
    path = Path(token).expanduser()
    try:
        if path.resolve() == Path(__file__).resolve() or not path.is_file() or path.stat().st_size >= 1_000_000:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def bash_verdict(command):
    """None when allowed, otherwise the reason. A line has to write to GitHub and set a label at once."""
    inputs = [text for text in (read(token) for token in INPUT.findall(command)) if text is not None]
    label_in_inputs = any(LABEL in text for text in inputs)
    texts = [("the command", command)] + [(token, read(token)) for token in EXECUTED.findall(command)]
    for where, text in texts:
        if not text or not (LABEL in text or label_in_inputs):
            continue
        for line in text.splitlines():
            if GH_WRITE.search(line) and SETTING.search(line):
                return f"{where} sets or removes the label {LABEL} on GitHub"
    return None


def mcp_verdict(tool, tool_input):
    """None when allowed, otherwise the reason. A GitHub MCP tool that writes and names the label."""
    match = MCP_GITHUB.match(tool)
    if not match or MCP_READ.search(match.group("tool")):
        return None
    if LABEL in json.dumps(tool_input):
        return f"the MCP tool {tool} writes the label {LABEL} on GitHub"
    return None


def verdict(event):
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input") or {}
    if tool == "Bash":
        return bash_verdict(tool_input.get("command", ""))
    return mcp_verdict(tool, tool_input)


def self_test():
    # the flag is kept off the line of the gh call, so that this file does not read as a command that sets the label
    add = "--add-label"
    edit = "gh pr edit 12 "
    refused = [{"tool_name": "Bash", "tool_input": {"command": edit + add + " " + LABEL}},
               {"tool_name": "mcp__github__issue_write", "tool_input": {"labels": [LABEL]}}]
    allowed = [{"tool_name": "Bash", "tool_input": {"command": edit + add + " P3"}},
               {"tool_name": "mcp__github__list_issues", "tool_input": {"labels": [LABEL]}}]
    assert all(verdict(event) for event in refused)
    assert not any(verdict(event) for event in allowed)
    print(f"no-maintainer-read-label self-test: {len(refused)} refused, {len(allowed)} allowed, ok")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    if not isinstance(event, dict):
        return 0
    reason = verdict(event)
    if reason is None:
        return 0
    message = (f"Refused by no-maintainer-read-label.py: {reason}. Only the maintainer sets {LABEL}, after reading "
               "every changed line of the pull request (astrapi69/mystic-crypt-ui#732, #737); an agent never sets or "
               "removes it. Ask the maintainer to set it in the browser.")
    if LOG.parent.is_dir():
        try:
            with LOG.open("a", encoding="utf-8") as log:
                log.write(f"{datetime.now().isoformat(timespec='seconds')} REFUSED {reason}\n")
        except OSError:
            pass
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": "deny",
                                             "permissionDecisionReason": message}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
