# Security Policy

`mystic-crypt` is a cryptography library and a command line tool: encryptors and
decryptors, key generation and signing, obfuscation, post-quantum signatures and
key encapsulation, SRP and J-PAKE. A defect here can silently weaken something a
consumer believes is protected, so the reporting path below is deliberately not
the public issue tracker.

## Supported Versions

Only the current minor line receives security fixes. This is a
single-maintainer project, and supporting several lines at once is a promise it
could not keep.

The table names **lines, not releases**: the top row is the supported one, and a
patch release inside it changes nothing here. It is revised when a line ends,
not when a version number moves.

| Version | Supported          | Required JDK | Needs crypt-data |
|---------|--------------------|--------------|------------------|
| 13.x    | :white_check_mark: | 25 and above | 12.3             |
| 12.x    | :x:                | 25 and above | 12.0.0 - 12.2    |
| 11.x    | :x:                | 25 and above | 11.0.0 - 11.2    |
| 9.x     | :x:                | 17 and above | 9.4              |
| 8.x     | :x:                | 11 and above |                  |

There is no 10.x line - the versions went from 9.x to 11.0.0. If you are on an
older line, the fix for a reported vulnerability will be an upgrade to the
current one rather than a backport.

## Reporting a Vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting,
which is enabled on this repository:

[Report a vulnerability](https://github.com/astrapi69/mystic-crypt/security/advisories/new)

That keeps the report between you and the maintainer until a fix exists, and it
creates the draft advisory a CVE can later be issued from.

Please include, as far as you can:

- the version you found it in, and whether the current release is affected
- whether it is reachable through the library API, the command line tool, or both
- what an attacker gains - reading key material, forging a signature, recovering
  a passphrase, getting a weaker key than was asked for, and so on
- a way to reproduce it: a failing test is ideal, since this project fixes bugs
  test-first and yours would become the regression guard

### What happens next

This is a spare-time project, so no response time is promised that could not be
met. What is promised instead:

- a reply acknowledging the report, and whether it is reproducible
- if it is: a fix on the current line, a release, and an advisory crediting you
  unless you prefer otherwise
- if it is not, or it turns out to be intended behaviour: an explanation of why,
  rather than silence

### Defects found by the maintainer

A security defect that is found from the inside - during development, a review,
or an audit of this project's own code - is tracked in a public issue like any
other bug, because that is where its fix, its regression test and its discussion
already live. The rule above is about a report from outside, which must not be
public before a fix exists; it is not a reason to hide the maintainer's own
findings from the people running the code.

Both paths end in the same place: once the fixed release is out, the defect gets
a published advisory naming the affected versions and the fixed one. The
advisory follows the release, never precedes it.

## Two things specific to this project

### The runnable jar bundles its dependencies

Besides the library jar, each release publishes `mystic-crypt-<version>-all.jar`,
a runnable uber-jar for the command line tool. It contains every runtime
dependency: in 12.2 that is 9296 Bouncy Castle class entries beside 431 of this
project's own.

So an advisory against **Bouncy Castle** affects that artifact directly, and a
consumer of the uber-jar cannot swap the affected version out the way a Maven or
Gradle consumer of the plain library jar can. If you depend on the uber-jar,
track Bouncy Castle advisories as if they were ours, and expect the fix to be a
new mystic-crypt release rather than a dependency override.

### The command line tool can take secrets in the process list

Four commands take a secret: `encrypt` and `decrypt` through `--passphrase`,
`hash` and `verify` through `--password`. Anything passed that way is visible to
every other process on the machine, in the shell history, and in any process
listing a container platform records.

Each of the four has a `--passphrase-stdin` or `--password-stdin` counterpart -
checked by asking every command for its help, not by assuming - and those are the
ones to use anywhere the value is not disposable.
This is a documented property rather than a vulnerability - but a report that a
passphrase leaked through a process list is expected to say which of the two
forms was used.

## What belongs elsewhere

This library never implements cryptographic primitives itself - ciphers, hashes,
signatures, key derivation and random generation all come from the JDK or from
Bouncy Castle, and the code here only orchestrates them. A flaw in a primitive
itself belongs to whoever implements it:

- the JDK: <https://openjdk.org/groups/vulnerability/report>
- Bouncy Castle: <https://github.com/bcgit/bc-java/security/policy>
- `crypt-data` and `crypt-api`, the two libraries underneath this one, have their
  own reporting paths in their repositories

A flaw in *how this library uses* one of them - a key written in a format the
caller did not ask for, a passphrase left in memory, a comparison that is not
constant time, a CLI option that cannot be honoured but reports success - is
squarely in scope here.

[docs/CRYPTO_CAPABILITIES.md](docs/CRYPTO_CAPABILITIES.md) records what this
project implements and what it deliberately leaves to a protocol or
infrastructure layer, which is the fastest way to tell whether something is in
scope before writing a report.

## What this project already does

So that a report can start from what is known rather than from zero:

- **CodeQL** runs on every push and pull request to `master` and `develop`, plus
  weekly.
- **Dependabot security updates** are enabled.
- Test key material is generated at test runtime and never committed, so nothing
  in this repository is a real key.
- Every uncovered line and every surviving mutant is argued case by case in
  [docs/COVERAGE_EXCEPTIONS.md](docs/COVERAGE_EXCEPTIONS.md), with the measured
  numbers and the commit they were taken on in
  [docs/TESTING.md](docs/TESTING.md). A gap in the tests is a documented
  decision rather than an accident.
