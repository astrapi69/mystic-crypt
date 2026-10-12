#!/usr/bin/env python3
"""Refuses a pull request that would close an issue it does not name on a closing line of its own.

GitHub reads "fixed" before an issue number as a closing keyword whatever stands before it, so a
release pull request that listed an issue as "known and not fixed" closed it on the merge, twice in
astrapi69/mystic-crypt-ui (astrapi69/mystic-crypt-ui#555). This check lets a pull request close an
issue only when a line of the body or of a commit message says so and nothing else: "Closes #NN",
"Fixes #NN", "Resolves #NN" (any form and case of the three words), alone or followed by more
references.

The references checked are the union of two sources, so that the check cannot pass on a list
GitHub has not filled yet (it fills closingIssuesReferences a few seconds after a pull request is
opened): the references GitHub reports, and every keyword followed by a reference that this script
finds itself in the body and the commit messages.

Input, as JSON on standard input:
  {"repository": "owner/name", "body": "...", "commits": ["message", ...],
   "closing": ["owner/name#12", ...]}
Exit 0 when every reference is named on a closing line, 1 when one is not, 2 on input it cannot
read - a check that cannot read its input does not pass (fail closed).

Taken over from astrapi69/mystic-crypt-ui, where ClosingReferencesCheckTest tests it.
"""
import json
import re
import sys

KEYWORD = r"(?:close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved)"
REFERENCE = r"(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?#\d+"

# a reference after a closing keyword anywhere in a text, as GitHub reads it
ANYWHERE = re.compile(rf"\b{KEYWORD}\b\s*:?\s+({REFERENCE})", re.IGNORECASE)

# a line that is a closing line and nothing else: keyword, references, separators, and at most
# a list marker in front
CLOSING_LINE = re.compile(
    rf"^\s*(?:[-*]\s+)?{KEYWORD}\s*:?\s+{REFERENCE}"
    rf"(?:\s*(?:,|\band\b)?\s*(?:{KEYWORD}\s*:?\s+)?{REFERENCE})*\s*\.?\s*$",
    re.IGNORECASE)

ONE_REFERENCE = re.compile(r"(?:([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+))?#(\d+)")


def canonical(reference, repository):
    match = ONE_REFERENCE.fullmatch(reference.strip())
    if not match:
        raise ValueError(f"not a reference: {reference!r}")
    return f"{(match.group(1) or repository).lower()}#{match.group(2)}"


def main():
    try:
        data = json.load(sys.stdin)
        repository = data["repository"]
        texts = [data["body"] or ""] + list(data["commits"])
        reported = [canonical(reference, repository) for reference in data["closing"]]
    except (ValueError, KeyError, TypeError) as unreadable:
        print(f"closing-references: cannot read the input: {unreadable}")
        return 2

    found = set()
    named = set()
    for text in texts:
        for match in ANYWHERE.finditer(text):
            found.add(canonical(match.group(1), repository))
        for line in text.splitlines():
            if CLOSING_LINE.match(line):
                for match in ONE_REFERENCE.finditer(line):
                    named.add(canonical(match.group(0), repository))

    closing = sorted(set(reported) | found)
    unnamed = [reference for reference in closing if reference not in named]
    print(f"closing-references: {len(closing)} issue(s) this pull request would close "
          f"({len(reported)} reported by GitHub, {len(found)} found in the text), "
          f"{len(closing) - len(unnamed)} named on a closing line")
    for reference in unnamed:
        owner_name, number = reference.split("#")
        shown = f"#{number}" if owner_name == repository.lower() else reference
        print(f"  NOT NAMED: {reference} would be closed by the merge, but no line says only "
              f"'Closes {shown}'. Reword the text that reads as a closing keyword, or name it on a "
              f"line of its own if it is meant to close.")
    return 1 if unnamed else 0


if __name__ == "__main__":
    sys.exit(main())
