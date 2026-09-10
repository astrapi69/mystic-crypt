# FLOSS/fund application, draft

Status: draft for review, not submitted. Every number in it was retrieved on 2026-09-10 and is
reproducible with the command next to it.

---

## Applicant

**Project:** mystic-crypt (`io.github.astrapi69:mystic-crypt`), MIT, JVM.
**Repository:** https://github.com/astrapi69/mystic-crypt

The library is the applicant, not the desktop application. FLOSS/fund looks for demonstrable use,
and use is demonstrable for the artifact that is published on Maven Central and consumed by other
builds. The desktop application `mystic-crypt-ui` is named as a dependent project and as where two
of the milestones land, not as the applicant.

---

## What this is, in one paragraph

mystic-crypt is a cryptography library and command line tool for the JVM: it generates key pairs,
converts between the key and certificate formats that tools in this space keep disagreeing about
(PEM, DER, PKCS#1, PKCS#8), computes checksums and message authentication codes, and encrypts files
and text through Bouncy Castle rather than hand-rolled primitives. On top of it sits a desktop
application that turns the same operations into a workbench for the keys and secrets a developer or
administrator handles every day, with an encrypted local vault as one of its functions rather than
its purpose. The audience is the people who deal with SSH keys, certificates, signing keys and API
tokens, and who use four separate tools and a text file for it today.

---

## Usage evidence

| Fact | Value | How to check |
|---|---|---|
| First release on Maven Central | 2015-04-24 | directory listing under `de/alpharogroup/mystic-crypt/` |
| Releases under the original coordinates | 46 | `maven-metadata.xml` for `de.alpharogroup:mystic-crypt` |
| Releases under the current coordinates | 18 | `maven-metadata.xml` for `io.github.astrapi69:mystic-crypt` |
| Latest release | 13.0, published 2026-09-09 | `<latest>` in that metadata |
| Licence | MIT | repository metadata |
| Repository age | created 2015-04-22 | GitHub API |
| Stars / forks | 11 / 6 | GitHub API |

**Download numbers are deliberately absent.** Maven Central publishes no per-artifact download
statistics through a public endpoint; the figures exist only behind the Central Portal login of the
publishing account. They can be supplied on request, and they are not estimated here. A guessed
number in a funding application is worth less than none.

Ten years of continuous publication and a release two days ago are the honest form of the same
claim: this is maintained, not archived.

---

## Milestones applied for

Two, both mandatory work in the next six months regardless of funding, and both free of any
generative-AI component. That last point is deliberate: it keeps the application answerable without
a discussion the work does not need.

### Milestone 1: a lossless KeePass (KDBX) round trip

**Problem.** Importing a KDBX database and exporting it again does not return what went in. Entry
identity is regenerated, timestamps are replaced, and history is dropped. Measured in the dependent
project: the export writes a fresh UUID and fresh timestamps per entry, so a round trip through this
application silently rewrites the metadata a KeePass user depends on.

**Why it matters beyond this project.** KDBX is the de facto interchange format for local password
storage. A tool that cannot round-trip it losslessly cannot be a bridge; it can only be a one-way
door. Fixing it makes migration in both directions safe, which is what lets people try an
alternative without committing to it.

**Deliverables.**
- Entry identity preserved across import and export, including entries created in the application.
- Creation, modification and access timestamps preserved rather than regenerated.
- History entries preserved or, where the model cannot hold them, refused with a message that says
  what would be lost, instead of dropped silently.
- A round-trip test with a real KDBX file that asserts equality of identity and timestamps, not
  only of titles and passwords.

**Acceptance.** A KDBX file imported and exported again compares equal on identity, timestamps and
entry count. The test is in the repository and runs in CI.

**Requested: 7,000 USD.**

### Milestone 2: keys as first-class entries

**Problem.** A key or a certificate is stored as an attachment, which means the application knows
it as bytes and nothing else. Everything it can do with keys, and it can do a lot, lives in
separate tool windows disconnected from the entry the key belongs to.

**Deliverables.**
- An entry type for key material carrying format, algorithm, fingerprint and, for certificates, the
  expiry date, filled by reading the key rather than typed by the user.
- The operations the library already provides, bound to the entry: convert the format, export the
  public half, show the fingerprint, compute a checksum.
- An expiry view: what becomes invalid within a chosen period.
- Tests that drive each operation through the running application against real key material.

**Acceptance.** A key imported as an entry reports its own algorithm and fingerprint, converts
between the four formats without leaving the entry, and an expiring certificate appears in the
expiry view before it expires.

**Requested: 5,000 USD.**

### Total requested: 12,000 USD

At the lower end of the range on purpose. A first application asking for a modest amount against
two verifiable milestones is a better proposition than one asking for the maximum, and the work is
scoped so that a smaller grant still delivers something whole: milestone 1 alone is a complete,
useful result.

---

## Which repository the work lands in

Both milestones land in `mystic-crypt-ui`, the dependent desktop application, while the applicant
is the library. That is stated plainly rather than blurred:

- The library supplies the operations both milestones build on and gains the pieces they need
  (identity and timestamp handling for the KDBX model, format metadata for key entries).
- The application is where a user meets them.
- Both repositories are maintained by the same person, under the same licence, in the same release
  discipline.

If the programme requires the funded work to land inside the applicant repository, milestone 2 can
be re-cut so that the entry model and the key metadata are library work with a thin consumer in the
application. Milestone 1 cannot: KDBX handling lives in the application today.

---

## Not applied for here

The following are real and planned, and they are deliberately kept out of this application so the
two funders are not asked for the same work:

- **Secrets in the build**: a Gradle plugin and a Maven counterpart that resolve secrets from an
  unlocked local vault instead of cleartext in `gradle.properties`, environment variables and CI
  secrets. This is the larger, newer capability and belongs in the NLnet application.
- **The overwrite rule and its shared helper** (data loss on writing over existing files) and the
  plugin lock harness. Both are ordinary maintenance obligations of the next release, not fundable
  new capability.

### A correction to the earlier split

The plan this draft came from assigned the **close path** and the **automatic lock** to the NLnet
application. Both are finished: they were closed on 2026-09-09 in the dependent project, together
with the vault-identity and timestamp issues around them. Applying for them would be applying for
completed work.

The NLnet application therefore needs a different milestone, and the build-secrets capability above
is the candidate: it is new, it is substantial, and nothing about it is done.

---

## Before submitting

- [ ] Publish a `funding.json` manifest at the location the programme expects, and check its
      current schema version against the programme page rather than against this note.
- [ ] Decide whether the applicant is the library alone or the library plus the application, and
      make the milestone section match that decision.
- [ ] Retrieve the download figures from the Central Portal and either include them or leave the
      row out, but do not estimate.
- [ ] Have someone who is not the author read the one-paragraph description and say what they think
      the project is. If the answer is "a password manager", the paragraph has failed.
