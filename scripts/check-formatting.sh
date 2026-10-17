#!/usr/bin/env bash
#
# Refuses a commit whose files Spotless would format (#200; the pattern of astrapi69/mystic-crypt-ui#592). The pre-commit hook runs it; CI checks
# the same with spotlessCheck in the build, which is where a forgotten spotlessApply used to surface,
# a gate run or a CI run later.
#
# Only what Spotless covers in this build counts, and only when the commit stages it:
#   src/**/*.java                          spotlessJavaCheck
#   *.gradle, *.md, .gitignore at the top  spotlessMiscCheck
# The plugin builds have no Spotless of their own, and a commit that touches nothing of the above
# costs no Gradle run. With a daemon running, a check takes under a second (measured in mystic-crypt-ui
# on 2026-10-17: 0.5 to 0.9 s; 5.3 s without one).
#
# Spotless checks the files as they are in the working tree, so a file staged in one form and edited
# further is checked in its edited form.
#
#   scripts/check-formatting.sh            GRADLEW overrides the Gradle wrapper, for the test
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
gradlew="${GRADLEW:-$root/gradlew}"

java=false
misc=false
while IFS= read -r -d '' path; do
  case "$path" in
    src/*.java) java=true ;;
    */*) ;;
    *.gradle | *.md | .gitignore) misc=true ;;
  esac
done < <(git -C "$root" diff --cached --name-only --diff-filter=ACMR -z)

tasks=()
[ "$java" = true ] && tasks+=(spotlessJavaCheck)
[ "$misc" = true ] && tasks+=(spotlessMiscCheck)
[ "${#tasks[@]}" -gt 0 ] || exit 0

if output="$("$gradlew" -p "$root" "${tasks[@]}" -q --console=plain 2>&1)"; then
  exit 0
fi
{
  printf '%s\n' "$output"
  echo
  echo "==> commit refused: Spotless would format the files named above (#200)"
  echo "    format them:      ./gradlew spotlessApply"
  echo "    then stage them again with git add, and commit again"
} >&2
exit 1
