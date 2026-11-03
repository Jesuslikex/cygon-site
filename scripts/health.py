#!/usr/bin/env python3
"""Fail (exit 1) when any feed has had no good refresh for MAX_AGE_H hours.

Runs after deploy, so a stale feed never blocks publishing; the failed run
triggers GitHub's failure email and the workflow's alert issue.
"""
import datetime as dt, json, os, sys

MAX_AGE_H = float(os.environ.get("MAX_AGE_H", "12"))
h = json.load(open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "site", "health.json")))
now = dt.datetime.now(dt.timezone.utc)
bad = []
for name, t in h["fresh"].items():
    try:
        age = (now - dt.datetime.strptime(t, "%Y-%m-%dT%H:%MZ").replace(tzinfo=dt.timezone.utc)).total_seconds() / 3600
    except ValueError:
        age = float("inf")
    print(f"{name}: last good {t or 'never'} ({age:.1f} h ago)")
    if age > MAX_AGE_H:
        bad.append(f"{name} (last good {t or 'never'})")
msg = "Stale for more than %g h: %s" % (MAX_AGE_H, ", ".join(bad)) if bad else "All feeds fresh"
out = os.environ.get("GITHUB_OUTPUT")
if out:
    with open(out, "a") as f:
        f.write(f"message={msg}\n")
print(msg)
if bad:
    print(f"::error title=Stale data::{msg}")
    sys.exit(1)
