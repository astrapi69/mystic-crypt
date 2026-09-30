#!/usr/bin/env bash
#
# Refuses commits that credit a non-human collaborator: as a co-author trailer (#373), or as the
# commit's author or committer (#444).
#
# coding-standards.md has forbidden this since 13444b67 (2026-08-25), and 112 of the 212 non-merge
# commits on develop after that day carried the trailer anyway (measured 2026-09-15). Not one of
# them carried the exception note the rule requires. The reason is not carelessness: the tooling
# that writes these commits instructs the opposite, and a rule that lives only in prose is followed
# when somebody happens to remember it (#248, #373).
#
# One script, two callers, so what counts as a violation is defined in exactly one place:
#
#   scripts/check-commit-provenance.sh --message-file <path>   the commit-msg hook, before the
#                                                              commit exists
#   scripts/check-commit-provenance.sh --range <base>..<head>  CI, on the commits of a pull request
#
# The hook catches it early and the range catches it for certain: a hook has to be installed
# locally (make install-hooks) and is absent in a fresh clone or worktree - which is precisely the
# situation where a session starts without knowing the rule.
#
# Exceptions are the ones the rule already allows: a commit body carrying a line
#
#   Co-Author-Exception: <reason>
#
# is let through, because that is the rule's "explicit note in the commit body" made checkable.
set -euo pipefail

# Names and addresses that identify a non-human co-author. Matched case-insensitively against the
# VALUE of a Co-Authored-By trailer, never against the commit's prose - a commit may discuss Claude
# or a bot without crediting one.
NON_HUMAN_PATTERN='anthropic\.com|\bclaude\b|\[bot\]|\bcopilot\b|noreply@github\.com|\bchatgpt\b|\bopenai\b|\bcursor\b|\bdevin\b|\bcodex\b'

# The same, for the author and committer of a commit (#444). Narrower on purpose: GitHub commits
# every web merge as 'GitHub <noreply@github.com>', which is a machine recording a human's click,
# not a collaborator. A commit authored under the AI tool's identity carries no trailer at all -
# and GitHub turns exactly that author into a Co-authored-by trailer when it squash-merges.
NON_HUMAN_IDENTITY_PATTERN='anthropic\.com|\bclaude\b|\bcopilot\b|\bchatgpt\b|\bopenai\b|\bcursor\b|\bdevin\b|\bcodex\b'

say() { printf '%s\n' "$*"; }
die() { printf 'check-commit-provenance: %s\n' "$*" >&2; exit 1; }

has_exception()
{
	printf '%s\n' "$1" | grep -qiE '^[[:space:]]*Co-Author-Exception:[[:space:]]*[^[:space:]]'
}

# Prints the offending trailers and identities of one commit, empty when there are none. The
# identities are given as lines "Author: name <email>" and "Committer: name <email>".
offending_lines()
{
	local message="$1" identities="$2"
	if has_exception "$message"; then
		return 0
	fi
	printf '%s\n' "$message" \
		| grep -iE '^[[:space:]]*Co-Authored-By:' \
		| grep -iE "$NON_HUMAN_PATTERN" || true
	printf '%s\n' "$identities" | grep -iE "$NON_HUMAN_IDENTITY_PATTERN" || true
}

refuse()
{
	local subject="$1" trailers="$2"
	cat >&2 <<REFUSAL

  Refused: $subject

$(printf '%s\n' "$trailers" | sed 's/^/      /')

  A commit in this family of repositories does not credit a non-human
  collaborator, as a co-author or as its author or committer (the Git rule in
  mystic-crypt .claude/rules/workflow.md and mystic-crypt-ui
  .claude/rules/coding-standards.md; this script is the same file in every
  repository). An identity is fixed with git config user.name / user.email and
  git commit --amend --reset-author on an unpushed commit. Provenance is
  recorded in the maintainer's private journal, where it is complete, and not
  as a signature line in a public repository - a line saying AI was involved
  without saying how tells a reader nothing and reads as the whole story.

  Remove the trailer. If this commit genuinely needs one, say why in the body:

      Co-Author-Exception: <reason>

REFUSAL
}

MODE=""
ARGUMENT=""
while [ $# -gt 0 ]; do
	case "$1" in
		--message-file | --range)
			[ -n "$MODE" ] && die "give --message-file or --range, not both"
			MODE="$1"
			ARGUMENT="${2:?$1 needs a value}"
			shift 2
			;;
		*) die "unknown argument: $1 (usage: --message-file <path> | --range <base>..<head>)" ;;
	esac
done
[ -n "$MODE" ] || die "nothing to check - give --message-file <path> or --range <base>..<head>"

if [ "$MODE" = "--message-file" ]; then
	[ -r "$ARGUMENT" ] || die "cannot read the commit message file: $ARGUMENT"
	message="$(cat "$ARGUMENT")"
	# the commit does not exist yet, so its identity is the one git is about to give it
	identities="Author: $(git var GIT_AUTHOR_IDENT | sed 's/> .*/>/')
Committer: $(git var GIT_COMMITTER_IDENT | sed 's/> .*/>/')"
	trailers="$(offending_lines "$message" "$identities")"
	say "checked 1 commit message and its author and committer for a non-human collaborator"
	if [ -n "$trailers" ]; then
		refuse "$(printf '%s\n' "$message" | head -1)" "$trailers"
		exit 1
	fi
	say "no non-human collaborator"
	exit 0
fi

# --range: fail closed. A range that resolves to nothing is an unanswered question, not an answer -
# an empty commit set and a clean commit set must never print the same green (quality-checks.md).
git rev-parse --verify --quiet "${ARGUMENT%%..*}^{commit}" >/dev/null \
	|| die "the base of $ARGUMENT does not resolve to a commit - fetch it before checking, this
  check does not treat an unknown base as nothing to find"

mapfile -t commits < <(git rev-list --no-merges "$ARGUMENT")
if [ "${#commits[@]}" -eq 0 ]; then
	die "no commits in $ARGUMENT - a range with nothing in it is not a pass, it is a range that
  was built wrong"
fi

failed=0
for commit in "${commits[@]}"; do
	trailers="$(offending_lines "$(git log -1 --format=%B "$commit")" \
		"$(git log -1 --format='Author: %an <%ae>%nCommitter: %cn <%ce>' "$commit")")"
	if [ -n "$trailers" ]; then
		refuse "$(git log -1 --format='%h %s' "$commit")" "$trailers"
		failed=1
	fi
done

say "checked ${#commits[@]} commit(s) in $ARGUMENT - trailers, author and committer - for a non-human collaborator"
[ "$failed" -eq 0 ] || exit 1
say "no non-human collaborator"
