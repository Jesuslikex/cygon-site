#!/usr/bin/env python3
"""Pull public threat feeds and render site/index.html from template.html.

Feeds: IPsum (stamparm), CISA KEV, CVEProject cvelistV5 deltaLog, DB-IP country lite
(via sapics/ip-location-db). If a feed fails, the last good value is kept (from the live
site's data.json, then site/data.json, then scripts/seed-data.json), so the site never breaks.
Each feed's last good refresh time is stored in D["fresh"]; the page shows a delayed notice
when it gets old, and scripts/health.py fails the workflow so GitHub raises an alert.
"""
import bisect, collections, datetime as dt, ipaddress, json, os, random, sys, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "site")
UA = {"User-Agent": "cygon-site-builder"}

IPSUM = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
KEV = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
DELTA = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
GEO = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv"

FEED_SIZE = 968
NOW = dt.datetime.now(dt.timezone.utc)


def get(url, timeout=60):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


LIVE_DATA = os.environ.get("LIVE_DATA_URL", "https://cygon.xyz/data.json")


def load_prev():
    try:
        d = json.loads(get(LIVE_DATA, 30))
        if isinstance(d, dict) and d.get("snapshot"):
            print("prev data from", LIVE_DATA, d["snapshot"])
            return d
    except Exception as ex:
        print("live data.json unavailable:", ex, file=sys.stderr)
    for p in (os.path.join(OUT, "data.json"), os.path.join(ROOT, "scripts", "seed-data.json")):
        if os.path.exists(p):
            return json.load(open(p))
    return {}


def geo_table():
    starts, ends, ccs = [], [], []
    for line in get(GEO, 120).decode().splitlines():
        a, b, cc = line.split(",")[:3]
        starts.append(int(ipaddress.IPv4Address(a)))
        ends.append(int(ipaddress.IPv4Address(b)))
        ccs.append(cc)

    def look(ip):
        n = int(ipaddress.IPv4Address(ip))
        i = bisect.bisect_right(starts, n) - 1
        return ccs[i] if i >= 0 and n <= ends[i] else None

    return look


def ipsum_part(D, centroids):
    raw = get(IPSUM).decode()
    updated, rows = None, []
    for line in raw.splitlines():
        if line.startswith("# Last update:"):
            updated = line.split(":", 1)[1].strip()
        if not line or line.startswith("#"):
            continue
        ip, n = line.split()
        rows.append((ip, int(n)))
    look = geo_table()
    levels = collections.Counter()
    counts = collections.Counter()
    tagged = []
    for ip, n in rows:
        levels[str(min(n, 8))] += 1
        cc = look(ip)
        if cc and cc != "ZZ":
            counts[cc] += 1
            tagged.append((ip, n, cc))
    # sample for the replay feed, weighted toward higher-confidence hosts
    rnd = random.Random(NOW.strftime("%Y%m%d%H"))
    hi = [t for t in tagged if t[1] >= 3]
    lo = [t for t in tagged if t[1] < 3]
    pick = rnd.sample(hi, min(len(hi), int(FEED_SIZE * 0.75)))
    pick += rnd.sample(lo, min(len(lo), FEED_SIZE - len(pick)))
    pick = [t for t in pick if t[2] in centroids]
    rnd.shuffle(pick)
    mask = lambda ip: ".".join(ip.split(".")[:2]) + ".x.x"
    D.update(
        ipsumUpdated=updated or D.get("ipsumUpdated", ""),
        totalIps=len(rows),
        levels={k: levels.get(k, 0) for k in ["8", "7", "6", "5", "4", "3", "2", "1"]},
        topCountries=[[c, n] for c, n in counts.most_common(12)],
        countries={c: centroids[c] for c in counts if c in centroids},
        allCounts={c: n for c, n in counts.items() if c in centroids},
        feed=[[mask(ip), n, cc] for ip, n, cc in pick],
    )


def kev_part(D):
    data = json.loads(get(KEV))
    v = data["vulnerabilities"]
    v.sort(key=lambda x: (x["dateAdded"], x["cveID"]), reverse=True)
    cutoff = (NOW - dt.timedelta(days=30)).strftime("%Y-%m-%d")
    D.update(
        kevTotal=len(v),
        kev30=sum(1 for x in v if x["dateAdded"] >= cutoff),
        kev=[
            {
                "id": x["cveID"],
                "vendor": x["vendorProject"],
                "product": x["product"],
                "name": x["vulnerabilityName"],
                "added": x["dateAdded"],
                "ransom": x.get("knownRansomwareCampaignUse", "Unknown"),
            }
            for x in v[:12]
        ],
    )


def cve_detail(link, cid, t):
    rec = json.loads(get(link, 30))
    cna = rec.get("containers", {}).get("cna", {})
    aff = (cna.get("affected") or [{}])[0]
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    score = sev = None
    metrics = list(cna.get("metrics", []))
    for adp in rec.get("containers", {}).get("adp", []) or []:
        metrics += adp.get("metrics", []) or []
    for m in metrics:
        for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if k in m:
                score = m[k].get("baseScore")
                sev = m[k].get("baseSeverity")
                break
        if score is not None:
            break
    return {
        "id": cid,
        "vendor": aff.get("vendor", ""),
        "product": aff.get("product", ""),
        "desc": desc[:180],
        "score": score,
        "sev": sev,
        "t": t[:16],
    }


def cve_part(D):
    delta = json.loads(get(DELTA))
    since = NOW - dt.timedelta(hours=24)
    new, seen = [], set()
    for e in delta:
        ft = dt.datetime.fromisoformat(e["fetchTime"].replace("Z", "+00:00"))
        if ft < since:
            continue
        for c in e.get("new", []):
            if c["cveId"] not in seen:
                seen.add(c["cveId"])
                new.append(c)
    new.sort(key=lambda c: c.get("dateUpdated", ""), reverse=True)
    out = []
    for c in new:
        if len(out) >= 14:
            break
        try:
            d = cve_detail(c["githubLink"], c["cveId"], c.get("dateUpdated", ""))
            if d["desc"] and "** REJECT" not in d["desc"]:
                out.append(d)
        except Exception as ex:
            print("cve skip", c["cveId"], ex, file=sys.stderr)
    D["cvesNew24h"] = len(new)
    if out:
        D["cves"] = out


STATUS_HOSTS = [h for _, h in json.load(open(os.path.join(ROOT, "scripts", "services.json")))]


def status_part(D):
    out = []
    for h in STATUS_HOSTS:
        try:
            req = urllib.request.Request(f"https://{h}/api/v2/summary.json", headers={**UA, "Origin": "https://jesuslikex.github.io"})
            with urllib.request.urlopen(req, timeout=20) as r:
                cors = r.headers.get("Access-Control-Allow-Origin")
                j = json.loads(r.read())
            inc = next((i for i in j.get("incidents", []) if i.get("status") != "resolved"), None)
            out.append({"host": h, "indicator": j["status"]["indicator"], "description": j["status"]["description"], "incident": inc["name"] if inc else ""})
            print("status", h, j["status"]["indicator"], "cors=", cors)
        except Exception as ex:
            print("status skip", h, ex, file=sys.stderr)
    if not out:
        raise RuntimeError("no status pages reachable")
    D["status"] = out


HISTORY = os.environ.get("HISTORY_URL", "https://raw.githubusercontent.com/Jesuslikex/cygon-site/status-history/status.json")
LEVEL = {"none": 0, "maintenance": 0, "minor": 1, "major": 2, "critical": 3}


def history_part(D):
    """Daily incident bars, uptime and an incident timeline from the status-history branch."""
    db = json.loads(get(HISTORY, 30))
    pt = lambda s: dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    today = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    day0 = today - dt.timedelta(days=89)
    services, timeline = [], []
    for name, host in json.load(open(os.path.join(ROOT, "scripts", "services.json"))):
        h = db["hosts"].get(host)
        if not h or "coverage_from" not in h:  # never reached yet
            continue
        cov = max(pt(h["coverage_from"]), NOW - dt.timedelta(days=90))
        spans = []
        for i in h["incidents"].values():
            a, b = pt(i["start"]), pt(i["end"]) if i["end"] else NOW
            spans.append((a, b, LEVEL.get(i["impact"], 0)))
            timeline.append({"svc": name, "name": i["name"], "impact": i["impact"], "start": i["start"], "end": i["end"], "link": i["link"]})
        days = []
        for k in range(90):
            ds = day0 + dt.timedelta(days=k)
            de = ds + dt.timedelta(days=1)
            if de <= cov:
                days.append(-1)
                continue
            days.append(max([lv for a, b, lv in spans if a < de and b > ds] or [0]))

        def uptime(n):
            start = max(NOW - dt.timedelta(days=n), cov)
            total = (NOW - start).total_seconds()
            if total < 3600:
                return None
            bad = sorted((max(a, start), min(b, NOW)) for a, b, lv in spans if lv >= 2 and b > start)
            down, cur = 0, None
            for a, b in bad:  # union of overlapping major/critical spans
                if cur and a <= cur[1]:
                    cur = (cur[0], max(cur[1], b))
                else:
                    if cur:
                        down += (cur[1] - cur[0]).total_seconds()
                    cur = (a, b)
            if cur:
                down += (cur[1] - cur[0]).total_seconds()
            return round(100 * (1 - down / total), 3)

        services.append({"name": name, "host": host, "days": days, "up30": uptime(30), "up90": uptime(90),
                         "n30": sum(1 for a, b, lv in spans if b > NOW - dt.timedelta(days=30))})
    timeline.sort(key=lambda x: x["start"], reverse=True)
    if not services:
        raise RuntimeError("history file has no services yet")
    D["history"] = {"day0": day0.strftime("%Y-%m-%d"), "services": services, "timeline": timeline[:30],
                    "changes": db.get("changes", [])[-20:][::-1]}


def fill_csp(html):
    """Put the hashes of the page's executable inline scripts and the status hosts into the meta CSP."""
    import base64, hashlib, re
    hashes = []
    for attrs, body in re.findall(r"<script([^>]*)>(.*?)</script>", html, re.S):
        if "src=" in attrs or "application/ld+json" in attrs:
            continue
        digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
        hashes.append(f"'sha256-{digest}'")
    html = html.replace("/*CSP_SCRIPT*/", " ".join(hashes))
    return html.replace("/*CSP_CONNECT*/", " ".join(f"https://{h}" for h in STATUS_HOSTS))


def main():
    D = load_prev()
    centroids = json.load(open(os.path.join(ROOT, "scripts", "countries.json")))
    fresh = D.setdefault("fresh", {})
    prev_snap = D.get("snapshot")
    ok, failed = 0, []
    for name, fn in (("ipsum", lambda: ipsum_part(D, centroids)), ("kev", lambda: kev_part(D)), ("cve", lambda: cve_part(D)), ("status", lambda: status_part(D)), ("history", lambda: history_part(D))):
        try:
            fn()
            ok += 1
            fresh[name] = NOW.strftime("%Y-%m-%dT%H:%MZ")
            print("ok", name)
        except Exception as ex:
            failed.append(name)
            fresh.setdefault(name, prev_snap or "")
            print("FAILED", name, ex, file=sys.stderr)
            print(f"::warning title=Feed failed::{name}: {ex}")
    D["snapshot"] = NOW.strftime("%Y-%m-%dT%H:%MZ")
    os.makedirs(OUT, exist_ok=True)
    tpl = open(os.path.join(ROOT, "template.html")).read()
    blob = json.dumps(D, separators=(",", ":")).replace("</", "<\\/")
    html = tpl.replace("/*DATA*/null/*END*/", blob)
    html = fill_csp(html)
    open(os.path.join(OUT, "index.html"), "w").write(html)
    json.dump(D, open(os.path.join(OUT, "data.json"), "w"), separators=(",", ":"))
    open(os.path.join(OUT, ".nojekyll"), "w").close()
    import shutil
    st = os.path.join(ROOT, "static")
    if os.path.isdir(st):
        shutil.copytree(st, OUT, dirs_exist_ok=True)
    health = {"snapshot": D["snapshot"], "fresh": fresh, "failed": failed}
    json.dump(health, open(os.path.join(OUT, "health.json"), "w"), indent=1)
    summ = os.environ.get("GITHUB_STEP_SUMMARY")
    if summ:
        with open(summ, "a") as f:
            f.write(f"### Feed refresh {D['snapshot']}\n\n| feed | last good |\n|---|---|\n")
            for k, v in fresh.items():
                f.write(f"| {k} | {v}{' (failed this run)' if k in failed else ''} |\n")
    print(f"built: {ok}/5 feeds, {D.get('totalIps')} ips, {len(D.get('feed', []))} feed rows")
    if ok == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
