# Status of the project page

Last updated: 2026-10-30. Page: https://astrapi69.github.io/mystic-crypt/ (branch `gh-pages`, file `index.html`).

## Done in the search-optimisation PR

- Title, meta description, canonical URL, robots meta and the lang attribute are set.
- Open Graph and Twitter Card tags point at `og-image.png` (1200 x 630, in this branch).
- JSON-LD: `SoftwareSourceCode` for the library and `FAQPage` for the questions visible on the page.
  Both were checked with `schema-dts` and `tsc` (see the PR for the command and output).
- `robots.txt` and `sitemap.xml` are in the branch.
- The page has one h1, sections for getting started, examples, features, command line, FAQ, security
  and documentation. Maven and Gradle coordinates show the current release 13.8, checked 30 October 2026.
- The page loads nothing from other hosts. The footer says so.

## Status after the merge

- Merged on 30 October 2026: pull request 225 (`5e935431`). The page content is on `gh-pages`.
- Not yet verified: the live page at https://astrapi69.github.io/mystic-crypt/. The check environment
  could not reach github.io, so the live rendering, the social preview and the sitemap fetch still need a
  check from a browser. Also: the links the environment could not reach (central.sonatype.com, javadoc.io,
  ko-fi.com, liberapay.com, PayPal) need a check from a normal browser.
- Open repository tensions, not on the page: `README.md` still has the `${latestVersion}` placeholder, and
  the sources disagree on whether the JDK provides ML-KEM and ML-DSA (see the PR description).

## Measurements

The numbers before and after the PR are in the PR description (Lighthouse, page weight, requests,
contrast, layout at phone width, link check).

## Open items for Aster

1. **Google Search Console**: add the property `https://astrapi69.github.io/mystic-crypt/` and submit
   `https://astrapi69.github.io/mystic-crypt/sitemap.xml`. Google issues a verification token. Send it to
   me and I add it to the page as a meta tag or a file in this branch.
2. **Bing Webmaster Tools**: the same, with the same sitemap URL. The verification code is also
   yours to send.
3. **Repository description and topics** on GitHub. Proposal, not yet set:
   - Description: `Java cryptography library: AES-GCM, Ed25519, X25519, ML-KEM, ML-DSA, PEM/PKCS#8 and OpenPGP key reading, Argon2id. Requires JDK 25.`
   - Topics: `java`, `cryptography`, `encryption`, `digital-signatures`, `key-agreement`, `post-quantum-cryptography`, `bouncy-castle`, `pem`, `pkcs8`, `openpgp`, `argon2`

## Open decisions

- `SoftwareApplication` is not in the JSON-LD. The page describes a library; the command line tool is a
  second way to use it. Adding it would be an honest second type, but it would not add search value
  on its own. Decide in review.
- A repository test that compares version, Maven coordinates and CLI commands between `README.md`, this
  page and the code is proposed in the PR, not built. It needs a go before anyone writes it.

## Not verified from the build environment

- Hosts that were unreachable from the environment where this page was checked: central.sonatype.com,
  javadoc.io, ko-fi.com, liberapay.com, paypal.com. Their links are unchanged from before the PR.
- Several GitHub pages returned 403 to the checking tool. Checked by `git ls-remote`: the wiki exists.
