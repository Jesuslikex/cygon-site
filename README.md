# $CYGON Threat Monitor

Static site on GitHub Pages. A scheduled GitHub Action (every 3 hours, plus on every push) pulls public feeds and renders `site/index.html` from `template.html`:

- IPsum threat feed (stamparm/ipsum)
- CISA Known Exploited Vulnerabilities
- CVE Program cvelistV5 delta log
- DB-IP country lite (via sapics/ip-location-db), CC BY 4.0

Run locally: `python3 scripts/build.py` then open `site/index.html`.

$CYGON is a community meme token with no intrinsic value and no promise of financial return. It is not affiliated with BI.ZONE, the Cyber Polygon exercise, or the World Economic Forum.
