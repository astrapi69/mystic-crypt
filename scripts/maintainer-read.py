#!/usr/bin/env python3
"""The maintainer-read status of a pull request (#732).

The maintainer looks at every pull request but does not read every line. For the few paths where a
wrong line loses or exposes data - here the vault format - a pull request that changes one of them
stays red until the maintainer has set the label read-by-maintainer himself. "Require review from
Code Owners" cannot say that here: every pull request is opened by the account astrapi69, which the
code owner would be, and GitHub does not let an author approve his own pull request.

.github/CODEOWNERS of the base branch is the single list of those paths. The script reads only the
forms that list needs, and refuses the rest instead of guessing what GitHub would make of it:
  /path/to/dir/    a directory: every file below it, at any depth
  /path/to/file    that file, and should the name be a directory, every file below it, as GitHub
                   reads a name without a trailing slash
  *                in either form, any characters within one path segment, never a /
Every pattern starts with / (anchored at the repository root) and has at least one owner; a line
starting with # is a comment, and the owners are not read further. A pattern with **, ?, [ ], !, \\
or # in it, one that is not anchored, or one without an owner makes the script exit 2. A pattern
with * reaches the files below a directory it matches as well, which is wider than GitHub reads
/docs/* and the safe side for a check that protects.

A changed listed path counts as read when the label read-by-maintainer is on the pull request now,
and the last time it was set, the maintainer set it himself: the last labeled event for it, by
created_at, has his login as actor and no GitHub App in performed_via_github_app. A label set
through an app, or from another account, does not count. The workflow removes the label on every
new push, so what was read is what is merged.

Input, as JSON on standard input:
  {"codeowners": "<the text of .github/CODEOWNERS>",
   "files": ["path/of/a/changed/file", ...],
   "labels": ["read-by-maintainer", ...],
   "events": [{"event": "labeled", "label": {"name": "read-by-maintainer"},
               "actor": {"login": "astrapi69"}, "performed_via_github_app": null,
               "created_at": "2026-11-04T10:00:00Z"}, ...],
   "maintainer": "astrapi69"}
files holds a renamed file under its new and its old name, so that moving a file out of a listed
path needs the label too; events is GET /repos/{owner}/{repo}/issues/{n}/events.
Output: one line, tab separated: the state (success or failure) and a description of at most 140
characters; standard error says what was compared, for the log. Exit 0, or 2 when it cannot decide:
input it cannot read, a CODEOWNERS that lists no path or a form it does not read, no changed file.
Then no status comes from it, and a required status that is not success blocks the merge (fail
closed).
"""
import json
import re
import sys

LABEL = "read-by-maintainer"
DESCRIPTION_LIMIT = 140
UNREAD_FORMS = re.compile(r"\*\*|[?\[\]!\\#]")


class Undecidable(Exception):
    """Input the check cannot decide on; no status comes from it."""


def matcher(pattern, number):
    def refused(why):
        return Undecidable(f"CODEOWNERS line {number}: {pattern} {why}")

    if UNREAD_FORMS.search(pattern):
        raise refused("uses a form the check does not read (**, ?, [ ], !, \\, #)")
    if not pattern.startswith("/"):
        raise refused("is not anchored at the repository root with a leading /")
    segments = pattern.strip("/").split("/")
    if "" in segments or "." in segments or ".." in segments:
        raise refused("names no path")
    name = "/".join("[^/]*".join(re.escape(part) for part in segment.split("*"))
                    for segment in segments)
    below = r"/.+" if pattern.endswith("/") else r"(?:/.+)?"
    return re.compile(name + below, re.DOTALL)


def patterns_of(codeowners):
    patterns = []
    for number, line in enumerate(codeowners.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pattern, *owners = stripped.split()
        if not owners:
            raise Undecidable(f"CODEOWNERS line {number}: {pattern} has no owner")
        patterns.append((number, pattern, matcher(pattern, number)))
    return patterns


def missing_read(labels, events, maintainer):
    """What keeps the label from counting as the maintainer's, or None when it counts."""
    if LABEL not in labels:
        return f"no {LABEL} label"
    settings = [event for event in events if event.get("event") == "labeled"
                and (event.get("label") or {}).get("name") == LABEL]
    if not settings:
        return f"{LABEL} is on it, but no event says who set it"
    if any(not isinstance(event.get("created_at"), str) for event in settings):
        raise Undecidable(f"a labeled event for {LABEL} carries no created_at")
    last = sorted(settings, key=lambda event: event["created_at"])[-1]
    app = last.get("performed_via_github_app")
    if app is not None:
        slug = app.get("slug") if isinstance(app, dict) else None
        return f"{LABEL} was set through the app {slug or 'of unknown name'}, not by {maintainer}"
    login = (last.get("actor") or {}).get("login")
    if not isinstance(login, str) or login.casefold() != maintainer.casefold():
        return f"{LABEL} was set by {login or 'an unknown account'}, not by {maintainer}"
    return None


def printable(text):
    return "".join(character if character.isprintable() else "?" for character in text)


def failure_description(missing, touched):
    head = f"{missing}: "
    more = f" and {len(touched) - 1} more" if len(touched) > 1 else ""
    path = printable(touched[0])
    room = DESCRIPTION_LIMIT - len(head) - len(more)
    if len(path) > room:
        path = "..." + path[-max(room - 3, 1):]
    return (head + path + more)[:DESCRIPTION_LIMIT]


def read(data):
    codeowners, files = data["codeowners"], data["files"]
    labels, events, maintainer = data["labels"], data["events"], data["maintainer"]
    if not (isinstance(codeowners, str) and isinstance(maintainer, str) and maintainer
            and all(isinstance(field, list) for field in (files, labels, events))
            and all(isinstance(path, str) for path in files)
            and all(isinstance(label, str) for label in labels)
            and all(isinstance(event, dict) for event in events)):
        raise Undecidable("the input has a field of the wrong type")
    return codeowners, list(dict.fromkeys(files)), labels, events, maintainer


def on_listed_paths(files, patterns):
    """Each changed file on a listed path, with the CODEOWNERS line that lists it."""
    touched = []
    for path in files:
        for number, pattern, match in patterns:
            if match.fullmatch(path):
                touched.append((path, number, pattern))
                break
    return touched


def decide(data):
    codeowners, files, labels, events, maintainer = read(data)
    patterns = patterns_of(codeowners)
    if not patterns:
        raise Undecidable("CODEOWNERS lists no path: a check that compares with nothing does "
                          "not pass")
    if not files:
        raise Undecidable("the pull request has no changed file: a check that read nothing does "
                          "not pass")

    touched = on_listed_paths(files, patterns)
    print(f"maintainer-read: {len(files)} changed file(s), {len(patterns)} listed path(s), "
          f"{len(touched)} changed file(s) on a listed path", file=sys.stderr)
    for path, number, pattern in touched:
        print(f"  {printable(path)} (CODEOWNERS line {number}: {pattern})", file=sys.stderr)

    if not touched:
        return "success", (f"none of the {len(files)} changed files is on one of the "
                           f"{len(patterns)} listed paths")
    missing = missing_read(labels, events, maintainer)
    if missing is None:
        return "success", (f"read by {maintainer}: {LABEL} on {len(touched)} of {len(files)} "
                           f"changed files on a listed path")
    return "failure", failure_description(missing, [path for path, _, _ in touched])


def main():
    try:
        state, description = decide(json.load(sys.stdin))
    except (ValueError, KeyError, TypeError, AttributeError) as unreadable:
        print(f"maintainer-read: cannot read the input: {unreadable!r}", file=sys.stderr)
        return 2
    except Undecidable as undecidable:
        print(f"maintainer-read: cannot decide: {undecidable}", file=sys.stderr)
        return 2
    print(f"{state}\t{printable(description)[:DESCRIPTION_LIMIT]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
