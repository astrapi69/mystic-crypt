# FLOSS/fund application, draft

Status: ready to submit, not submitted. Aster submits it; this file and the `funding.json` in the
repository root are what gets submitted. Every number was retrieved on 2026-09-10 and is
reproducible with the command or the source next to it.

## What the programme actually requires, read from the programme pages

| Question | Answer | Source |
|---|---|---|
| May an individual apply without a legal entity? | Yes. "Individuals, projects, groups, communities, or organisations can apply." The applicant "must have a bank account and the necessary tax documents (which vary between jurisdictions) to receive funds." | <https://floss.fund/faq/> |
| What may be requested? | "A project can apply for funding of up to $100,000 in one year", and "we accept requests in denominations of a minimum of $10,000 and multiples of $25,000 thereafter." | <https://floss.fund/faq/> |
| How is it submitted? | Write a `funding.json` manifest, publish it, and "Submit the URL to the directory" at <https://dir.floss.fund/submit>. A validator is at <https://dir.floss.fund/validate>. | <https://floss.fund/faq/>, <https://dir.floss.fund/submit> |
| Manifest format | funding.json **v1.1.0**, schema at <https://fundingjson.org/schema/v1.1.0.json>. Hosted on the project website or in the repository. | <https://fundingjson.org> |
| Is there a rule about generative AI? | **None.** Neither the FAQ nor the programme pages mention AI, LLMs, machine learning or generative tools. Projects are judged on "value, impact, criticality, and innovation". | <https://floss.fund/faq/> |
| How is it paid out? | "our team will reach out to you for the necessary paperwork (such as tax residency documents required by Indian laws) before processing the funds", up to four weeks by email. | <https://floss.fund/faq/> |

**Two consequences, and the first one changed this application.**

The requested sum had to move. 12,000 USD is not an accepted denomination: the minimum is 10,000
and everything above it goes in steps of 25,000. Inside the band that was agreed, 10,000 is the
only permitted figure, so that is what is requested, split 6,000 and 4,000 across the two
milestones.

The eligibility rule that could have stopped this does not: an individual may apply. What the
payout needs is a bank account and tax residency paperwork under Indian law, which is a form to
fill in, not a legal entity to found.

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

Two, both mandatory work in the next six months regardless of funding.

**On generative tooling.** The programme has no rule about it - checked, not assumed. The
commitment is made anyway, because it is in this application and therefore binds the execution:
these two milestones will not be predominantly machine-generated. Design, cryptographic decisions
and the tests that pin them are the maintainer's work.

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

**Requested: 6,000 USD.**

### Milestone 2: keys as first-class objects in the library

**Problem.** Key material is handled as opaque bytes. What a key is - its format, its algorithm,
its fingerprint, when the certificate around it expires - is known to whoever wrote the file and
not to the software holding it. Every consumer of the library that wants those properties reads
them off the key itself, or asks the user to type them in and hopes.

**Deliverables, in `mystic-crypt` itself.**
- A key description model that reads format, algorithm and fingerprint off the key rather than
  taking them on trust, and the certificate expiry where there is one.
- The operations the library already has, bound to that model: convert the format, export the
  public half, compute the fingerprint, compute a checksum.
- An expiry query: which of a set of keys becomes invalid within a given period.
- Tests against real key material for every algorithm the library can generate, not a sample.

**Consumer.** The desktop application uses the model as its first consumer, so the key becomes an
entry type there rather than an attachment. That part is deliberately the smaller half: the funded
result is in the library, where every project that already depends on it can use it.

**Acceptance.** Given a key file, the library reports its algorithm, format and fingerprint without
being told them, converts between the four formats through the model, and answers which keys in a
set expire inside a period.

**Requested: 4,000 USD.**

### Total requested: 10,000 USD

The minimum the programme accepts, and deliberately so. A first application asking for a modest
amount against two verifiable milestones is a better proposition than one asking for the maximum,
and the work is scoped so that a smaller grant still delivers something whole: milestone 1 alone is
a complete, useful result.

---

## Which repository the work lands in

Milestone 2 is library work: the key description model and its operations are built in
`mystic-crypt`, the applicant repository, and the desktop application is its first consumer. That
is the cut, not an option left open.

Milestone 1 lands in `mystic-crypt-ui`, because KDBX handling lives there and moving it would be a
different project than the one being funded. Both repositories are maintained by the same person,
under the same licence, in the same release discipline, and the application is listed in the
manifest as a project so a reviewer can see where the work happens rather than having to ask.

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

## Submitting

The manifest is `funding.json` in the root of this repository. Submit its URL here:

- Submission form: <https://dir.floss.fund/submit>
- Manifest URL to paste: `https://github.com/astrapi69/mystic-crypt/blob/develop/funding.json`
- Validator, worth running first: <https://dir.floss.fund/validate>

It validates against schema v1.1.0 locally, and the programme's validator is the one that counts -
measured, not assumed: the published schema file carries no length limit on a plan description
while the live validator enforces `should be of length 0 - 500`, and both plan descriptions were
over it on the first attempt. So the order is: write, run the live validator, then submit. Field
lengths as submitted, against the limits that actually apply:

| Field | Length | Limit |
|---|---|---|
| entity.description | 250 | 2000 |
| project descriptions | 453 / 306 | 2000 |
| channel descriptions | 116 / 80 | 500 |
| plan descriptions | 497 / 499 | 500, enforced by the validator only |

Before pasting the URL:

- [ ] Check the contact address in the manifest. It is the address the repository's commits carry,
      which is not necessarily the one to receive grant correspondence.
- [ ] Read the one-paragraph description aloud to someone who does not know the project. If they
      say "a password manager", the paragraph has failed.

Deliberately not done here: the download figures. Maven Central publishes none through a public
endpoint, and a guessed number is worth less than an absent one.

## The risk this application carries

The programme says: "Very new projects or projects with minimal usage are not considered for the
time being." Ten years of continuous releases answer the first half. The second half is thinner:
eleven stars and six forks are small numbers, and the download figures that would answer it
properly are not publicly retrievable. The honest reading is that this is a small, old, maintained
project rather than a widely known one, and the application says so rather than dressing it up.
