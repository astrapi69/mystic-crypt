#!/usr/bin/env python3
"""The release freeze as a status of every open pull request into develop
(astrapi69/mystic-crypt-ui#516, where ReleaseFreezeCheckTest tests it).

While a pull request from a release/* branch is open, nothing else merges into develop until the
release is tagged (vibe-coding.md, "Release freeze"). A rule in prose was kept by memory; this
script decides the status the workflow sets on each pull request's head commit, and develop's
branch protection requires it, so GitHub refuses the merge in the browser, through auto-merge and
through scripts/merge-pr.sh alike.

Two exceptions: the release pull request itself, and a pull request labelled release-content, for
a change that is part of the release (astrapi69/lethenon#160).

Input, as JSON on standard input, the open pull requests into develop:
  {"pulls": [{"number": 12, "head_ref": "release/8.9", "head_sha": "...",
              "labels": ["release-content"]}, ...]}
Output, one line per pull request, tab separated: head_sha, state (success or failure), number,
description. Exit 0, or 2 on input it cannot read - then no status is set, and a required status
that is never set blocks the merge (fail closed).
"""
import json
import sys

RELEASE_PREFIX = "release/"
EXEMPT_LABEL = "release-content"


def main():
    try:
        pulls = json.load(sys.stdin)["pulls"]
        for pull in pulls:
            pull["number"], pull["head_ref"], pull["head_sha"], pull["labels"]
    except (ValueError, KeyError, TypeError) as unreadable:
        print(f"release-freeze: cannot read the input: {unreadable}", file=sys.stderr)
        return 2

    releases = sorted((pull for pull in pulls if pull["head_ref"].startswith(RELEASE_PREFIX)),
                      key=lambda pull: pull["number"])
    for pull in pulls:
        if pull["head_ref"].startswith(RELEASE_PREFIX):
            state, description = "success", "the release pull request itself"
        elif EXEMPT_LABEL in pull["labels"]:
            state, description = "success", f"labelled {EXEMPT_LABEL}: part of the release"
        elif releases:
            first = releases[0]
            state = "failure"
            description = (f"release freeze: #{first['number']} ({first['head_ref']}) is open; "
                           f"nothing else merges until it is tagged")
        else:
            state, description = "success", "no release pull request is open"
        print(f"{pull['head_sha']}\t{state}\t{pull['number']}\t{description[:140]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
