#!/usr/bin/env python3
"""Pull public threat feeds and render site/index.html from template.html.

Feeds: IPsum (stamparm), CISA KEV, CVEProject cvelistV5 deltaLog, DB-IP country lite
(via sapics/ip-location-db). If a feed fails, the last good value from
site/data.json (or scripts/seed-data.json) is kept, so the site never breaks.
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


def load_prev():
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


def main():
    D = load_prev()
    centroids = json.load(open(os.path.join(ROOT, "scripts", "countries.json")))
    ok = 0
    for name, fn in (("ipsum", lambda: ipsum_part(D, centroids)), ("kev", lambda: kev_part(D)), ("cve", lambda: cve_part(D))):
        try:
            fn()
            ok += 1
            print("ok", name)
        except Exception as ex:
            print("FAILED", name, ex, file=sys.stderr)
    D["snapshot"] = NOW.strftime("%Y-%m-%dT%H:%MZ")
    os.makedirs(OUT, exist_ok=True)
    tpl = open(os.path.join(ROOT, "template.html")).read()
    blob = json.dumps(D, separators=(",", ":")).replace("</", "<\\/")
    html = tpl.replace("/*DATA*/null/*END*/", blob)
    open(os.path.join(OUT, "index.html"), "w").write(html)
    json.dump(D, open(os.path.join(OUT, "data.json"), "w"), separators=(",", ":"))
    open(os.path.join(OUT, ".nojekyll"), "w").close()
    print(f"built: {ok}/3 feeds, {D.get('totalIps')} ips, {len(D.get('feed', []))} feed rows")
    if ok == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
