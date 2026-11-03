# $CYGON Threat Monitor

Static site on GitHub Pages. A scheduled GitHub Action (every 3 hours, plus on every push) pulls public feeds and renders `site/index.html` from `template.html`:

- IPsum threat feed (stamparm/ipsum)
- CISA Known Exploited Vulnerabilities
- CVE Program cvelistV5 delta log
- DB-IP country lite (via sapics/ip-location-db), CC BY 4.0

If a feed fails, the build keeps its last good data (read back from the live `data.json`) and the page shows a "Delayed" notice once data is more than 6 hours old (or one source is more than 12 hours old). `scripts/health.py` fails the run when any feed has had no good refresh for 12 hours, and the workflow then opens a "Site data refresh is failing" issue, which closes itself on the next good run.

three.js (r128, MIT) and the globe texture are self-hosted from `static/`. The globe loads after the data panels, pauses when off screen, and lowers its quality on weak devices.

Run locally: `python3 scripts/build.py` then open `site/index.html`.

$CYGON is a community meme token with no intrinsic value and no promise of financial return. It is not affiliated with BI.ZONE, the Cyber Polygon exercise, or the World Economic Forum.
