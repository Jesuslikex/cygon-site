#!/usr/bin/env python3
"""Post service state changes to Telegram and/or X.

Usage: alert.py <changes.json> [--test]

Each channel is off until all of its secrets are set (see README):
  Telegram: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
  X:        X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_SECRET
One message per run, however many services changed.
"""
import base64, hashlib, hmac, json, os, secrets, sys, time, urllib.parse, urllib.request

SITE = "https://cygon.xyz/#outages"
ICON = {"none": "🟢", "minor": "🟠", "maintenance": "🔧", "major": "🔴", "critical": "🚨"}
WORD = {"none": "back to normal", "minor": "minor issues", "maintenance": "under maintenance",
        "major": "major outage", "critical": "critical outage"}


def message(changes, limit=None):
    lines = []
    for c in changes:
        line = f"{ICON.get(c['to'], '⚪')} {c['name']}: {WORD.get(c['to'], c['desc'])}"
        if c.get("incident") and c["to"] != "none":
            line += f" ({c['incident']})"
        lines.append(line)
    tail = f"\nLive tracker: {SITE}\n$CYGON"
    body = "\n".join(lines)
    if limit and len(body) + len(tail) > limit:
        body = body[: limit - len(tail) - 1].rsplit("\n", 1)[0] + "\n…"
    return body + tail


def post_json(url, payload, headers=None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, r.read()[:300]


def telegram(text):
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (tok and chat):
        print("Telegram: off (no TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID secrets)")
        return
    status, _ = post_json(f"https://api.telegram.org/bot{tok}/sendMessage",
                          {"chat_id": chat, "text": text, "disable_web_page_preview": True})
    print("Telegram: sent", status)


def x_post(text):
    keys = [os.environ.get(k) for k in ("X_API_KEY", "X_API_SECRET", "X_ACCESS_TOKEN", "X_ACCESS_SECRET")]
    if not all(keys):
        print("X: off (X_API_KEY / X_API_SECRET / X_ACCESS_TOKEN / X_ACCESS_SECRET not all set)")
        return
    ck, cs, at, ats = keys
    url = "https://api.x.com/2/tweets"
    q = lambda s: urllib.parse.quote(s, safe="")
    oauth = {"oauth_consumer_key": ck, "oauth_nonce": secrets.token_hex(16), "oauth_signature_method": "HMAC-SHA1",
             "oauth_timestamp": str(int(time.time())), "oauth_token": at, "oauth_version": "1.0"}
    params = "&".join(f"{q(k)}={q(v)}" for k, v in sorted(oauth.items()))  # JSON body is not signed
    base = "&".join(["POST", q(url), q(params)])
    oauth["oauth_signature"] = base64.b64encode(hmac.new(f"{q(cs)}&{q(ats)}".encode(), base.encode(), hashlib.sha1).digest()).decode()
    auth = "OAuth " + ", ".join(f'{q(k)}="{q(v)}"' for k, v in sorted(oauth.items()))
    status, _ = post_json(url, {"text": text}, {"Authorization": auth})
    print("X: posted", status)


def main():
    changes = json.load(open(sys.argv[1])) if os.path.exists(sys.argv[1]) else []
    if "--test" in sys.argv:
        changes = [{"name": "Test", "to": "none", "desc": "", "incident": ""}]
        tg, xt = "✅ $CYGON alerts are connected. Status changes will be posted here.\n" + SITE, None
    else:
        if not changes:
            print("no state changes")
            return
        tg, xt = message(changes), message(changes, 280)
    print(tg)
    errors = []
    for fn, text in ((telegram, tg), (x_post, xt)):
        if text is None:
            print(fn.__name__ + ": test posts go to Telegram only")
            continue
        try:
            fn(text)
        except Exception as ex:
            body = getattr(ex, "read", lambda: b"")()[:300]
            errors.append(f"{fn.__name__}: {ex} {body!r}")
    if errors:
        sys.exit("alert failed: " + "; ".join(errors))


if __name__ == "__main__":
    main()
