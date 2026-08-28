# Workflow (adopted from adaptive-learner, adapted for the crypt-* family)

These rules apply to mystic-crypt and, when working there, to crypt-api and
crypt-data as well.

## GITHUB-ISSUE-PFLICHT

Every bug fix needs a GitHub issue BEFORE the fix begins.

1. Search first (`gh issue list --search "<keywords>" --state all`); reopen a
   closed issue if the bug recurred, do not file a duplicate.
2. No fix without an issue - also retroactively: a NEW bug discovered while
   working on another one gets its own issue before it is fixed.
3. Commit subject and PR cite the issue: `(#NN)` or `Closes #NN`. `Refs` does
   not auto-close; `Closes`/`Fixes` does.
4. Verify the premise before filing: if the reported defect does not actually
   exist, surface that finding instead - a false issue is worse than none.

## PR-PFLICHT

Every pushed code change gets a pull request against `develop` - whether or
not the task asked for one. "No PR, wasn't requested" is not a valid
completion report. Opening the PR is the last step of the change, in the same
turn as the push.

Exceptions: no code change; a release freeze; the user explicitly said
"push only" for this task.

## Priority order (fixed)

1. Merge open PRs
2. Bugs
3. Infrastructure (CI, security, gates)
4. Cleanup/refactoring
5. Features
6. Release

## Release freeze

While a release PR or release branch is open and the version is not yet
tagged and published: no other merges to `develop`, no new feature PRs. Tag
first, then continue. Exception: a fix that blocks the release itself.

Releases follow the family order crypt-api -> crypt-data -> mystic-crypt;
a downstream release commit is pushed only when the upstream version is
actually resolvable on Maven Central.

## The downstream is built before the upstream is published

A published version cannot be replaced, so the check that it works belongs
BEFORE the upload, not after it. Upstream tests passing is not that check:
they test the library against itself, never against the consumer that will
get it.

Before `publishAllPublicationsToCentralPortal` for any repo in this family:

1. `./gradlew publishToMavenLocal` in the repo being released
2. point the downstream at that exact version (`mavenLocal()` is already first
   in `gradle/repositories.gradle`)
3. `./gradlew clean build` in the downstream - green, or the release does not
   go out
4. report what that run said, then ask

crypt-data 12.1 is why this is written down. Eight defects were fixed and
verified in crypt-data alone - 100% branch coverage, every mutant killed - and
published. mystic-crypt had never been compiled against it and failed four
tests immediately: the fix that made certificate signing name Bouncy Castle
for EC curves the JDK lacks made it refuse ML-DSA keys the JDK generates.
Because a version on Central is permanent, that cost a 12.2 that existed only
to undo it.

The same applies in the small: a change to crypt-api or crypt-data made while
working in mystic-crypt is built into the consumer locally before it is
proposed, not after it is merged.

## Git discipline

- Never `--amend` + force-push on an open PR - add a new commit instead
  (squash-merge still yields one clean commit).
- Never `git add -A` - add paths explicitly (PIT leaves files behind).
- Do not add `Co-Authored-By` trailers attributing non-human collaborators
  (AI tools, bots). Human co-authors only, unless an explicit note in the
  commit body states who authorized the attribution.
- Before preparing any release from a local copy: `git fetch` and compare
  with origin first - a stale local line has already diverged once.

## Claimed work is not executed work

Before building on any claimed change - your own previous step included -
verify the artifact, not the narrative: `git status`, `git log -1` (did HEAD
move?), the gate's own exit code. A pre-commit hook can roll a commit back
while printing "Passed".

After every merge, check BOTH: is the referenced issue closed, and did the
change actually land on the target branch (`git log origin/develop -- <path>`,
read the diff)? A squash freezes the branch at merge time; a push made after
the merge is silently lost.

## Mass edits

A proposed `sed`/regex sweep is inspected, not executed: read the matches,
map each to its real target, apply individually, diff the result.
