# gh-pages of mystic-crypt

This branch holds the project page served at <https://astrapi69.github.io/mystic-crypt/>.

It is one self-contained `index.html`: no build step, no package manager, no JavaScript framework.
`.nojekyll` tells GitHub Pages to serve it as is.

The page loads nothing from another host: no badge images, no web fonts, no script or stylesheet
from a CDN. A request to a third-party host on page load hands the visitor's IP address to that host
before the visitor has clicked anything
([#202](https://github.com/astrapi69/mystic-crypt/issues/202)). Other sites are reached through
plain links only, which is why the badge row holds text links where the main README shows badge
images.

The page summarizes the [README on `develop`](https://github.com/astrapi69/mystic-crypt/blob/develop/README.md)
and links to the documentation there. It deliberately carries no version number and no coverage or
mutation figures: the version is one click away on Maven Central, the measured numbers live in
[docs/TESTING.md](https://github.com/astrapi69/mystic-crypt/blob/develop/docs/TESTING.md). When the
README's quick start, feature list or CLI table changes, this page follows in a pull request against
`gh-pages`.
