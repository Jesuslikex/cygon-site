#!/usr/bin/env python3
"""Record service status changes and incidents into a JSON file (no database).

Usage: history.py <dir>   (the checkout of the status-history branch)

Every run polls each Statuspage summary + incidents API, merges incidents into
<dir>/status.json, and appends an entry to "changes" when a service's overall
indicator differs from the last run. Changes from this run are also written to
$CHANGES_OUT (for the alert step), and changed=true goes to $GITHUB_OUTPUT.
"""
import datetime as dt, json, os, sys, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICES = json.load(open(os.path.join(ROOT, "scripts", "services.json")))
UA = {"User-Agent": "cygon-status-history"}
KEEP_DAYS = 120
MAX_CHANGES = 1000
NOW = dt.datetime.now(dt.timezone.utc)
NOW_S = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r:
        return json.loads(r.read())


def iso(s):
    """Statuspage times look like 2026-11-03T15:02:11.123-05:00; store as UTC Z."""
    if not s:
        return None
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(d):
    path = os.path.join(d, "status.json")
    db = json.load(open(path)) if os.path.exists(path) else {"hosts": {}, "changes": []}
    # no "last checked" stamp on purpose: the file (and the branch) only changes when something real changes
    cutoff = (NOW - dt.timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_changes, reached = [], 0
    for name, host in SERVICES:
        h = db["hosts"].setdefault(host, {"name": name, "incidents": {}})
        h["name"] = name
        try:
            summ = get(f"https://{host}/api/v2/summary.json")
            incs = get(f"https://{host}/api/v2/incidents.json").get("incidents", [])
        except Exception as ex:
            print("skip", host, ex, file=sys.stderr)
            continue
        reached += 1
        for i in incs:
            created = iso(i.get("created_at"))
            if not created:
                continue
            h["incidents"][i["id"]] = {
                "name": i.get("name", ""),
                "impact": i.get("impact", "none"),
                "status": i.get("status", ""),
                "start": created,
                "end": iso(i.get("resolved_at")),
                "link": i.get("shortlink") or f"https://{host}/incidents/{i['id']}",
            }
        if h.get("coverage_from", "2000") < "2001":
            # only claim history back to the oldest incident the provider returned (or now, if none),
            # so days we know nothing about show as "no data" rather than a fake green
            starts = sorted(x["start"] for x in h["incidents"].values())
            h["coverage_from"] = starts[0] if starts else NOW_S
        h["incidents"] = {k: v for k, v in h["incidents"].items() if (v["end"] or NOW_S) >= cutoff}
        ind, desc = summ["status"]["indicator"], summ["status"]["description"]
        open_inc = next((i["name"] for i in summ.get("incidents", []) if i.get("status") != "resolved"), "")
        prev = h.get("indicator")
        if prev is not None and prev != ind:
            c = {"t": NOW_S, "host": host, "name": name, "from": prev, "to": ind, "desc": desc, "incident": open_inc,
                 "link": f"https://{host}"}
            db["changes"].append(c)
            run_changes.append(c)
            print("CHANGE", name, prev, "->", ind, desc)
        if prev != ind:
            h["since"] = NOW_S
        h.update(indicator=ind, description=desc, incident=open_inc)
    if not reached:
        sys.exit("no status pages reachable")
    db["changes"] = db["changes"][-MAX_CHANGES:]
    with open(path, "w") as f:
        json.dump(db, f, indent=1, sort_keys=True)
    out = os.environ.get("CHANGES_OUT")
    if out:
        json.dump(run_changes, open(out, "w"), indent=1)
    gh = os.environ.get("GITHUB_OUTPUT")
    if gh:
        with open(gh, "a") as f:
            f.write(f"changed={'true' if run_changes else 'false'}\n")
    print(f"reached {reached}/{len(SERVICES)}, {len(run_changes)} state changes")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
