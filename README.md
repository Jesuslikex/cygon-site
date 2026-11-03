# $CYGON Threat Monitor

Static site on GitHub Pages. A scheduled GitHub Action (every 3 hours, plus on every push) pulls public feeds and renders `site/index.html` from `template.html`:

- IPsum threat feed (stamparm/ipsum)
- CISA Known Exploited Vulnerabilities
- CVE Program cvelistV5 delta log
- DB-IP country lite (via sapics/ip-location-db), CC BY 4.0

If a feed fails, the build keeps its last good data (read back from the live `data.json`) and the page shows a "Delayed" notice once data is more than 6 hours old (or one source is more than 12 hours old). `scripts/health.py` fails the run when any feed has had no good refresh for 12 hours, and the workflow then opens a "Site data refresh is failing" issue, which closes itself on the next good run.

Status history: `.github/workflows/status-history.yml` polls the 13 status pages every 15 minutes and stores incidents and state changes as JSON on the `status-history` branch (`scripts/history.py`, no database). A state change triggers a redeploy. `build.py` turns that file into the 90-day bars, 30-day uptime and incident timeline in the Outages section.

Alerts: on a state change the same workflow runs `scripts/alert.py`, which posts one message per run to Telegram and/or X. Each channel stays off until its repo secrets exist (Settings → Secrets and variables → Actions):

- Telegram: `TELEGRAM_BOT_TOKEN` (from @BotFather) and `TELEGRAM_CHAT_ID` (your channel, e.g. `@cygon_alerts`, with the bot added as admin). Test with Actions → Status history → Run workflow → tick "Send a test message".
- X: `X_API_KEY`, `X_API_SECRET`, `X_ACCESS_TOKEN`, `X_ACCESS_SECRET` from a developer.x.com app with Read and Write permission.

Threat of the day: `.github/workflows/threat-of-day.yml` runs every morning at 07:05 UTC (and on demand from the Actions tab). It builds fresh data, then `scripts/threat_of_day.py` picks one headline (newest CISA exploited entry if added in the last 3 days, else the top CVSS 9+ CVE from the last 24 hours, else the country with the most flagged IPs; never the same headline two days running) and renders a 1200x675 card plus X post text of 275 weighted characters or fewer. Both are committed to the `threat-of-day` branch (`YYYY-MM-DD/card.png`, `post.txt`, and `latest.*`), and the site's "Threat of the day" section shows them with Copy text, Download card and Post on X buttons. Nothing is posted automatically. Fonts in `scripts/fonts` are Chakra Petch and JetBrains Mono (SIL OFL).

The page sets a Content-Security-Policy and referrer policy in meta tags (GitHub Pages can't send headers); `build.py` fills in the inline script hashes.

three.js (r128, MIT) and the globe texture are self-hosted from `static/`. The globe loads after the data panels, pauses when off screen, and lowers its quality on weak devices.

Run locally: `python3 scripts/build.py` then open `site/index.html`.

$CYGON is a community meme token with no intrinsic value and no promise of financial return. It is not affiliated with BI.ZONE, the Cyber Polygon exercise, or the World Economic Forum.
