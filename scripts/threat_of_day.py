#!/usr/bin/env python3
"""Daily "Threat of the day": a branded card image and a ready-to-post X text.

Usage: threat_of_day.py <data.json> <out_dir>

Reads the site's data.json (built by build.py from IPsum, CISA KEV, the CVE list and the
status history) and picks one headline:
  1. the newest CISA Known Exploited entry if it was added in the last 3 days,
  2. otherwise the highest scoring CVE published in the last 24 hours (CVSS 9+),
  3. otherwise the country with the most flagged IPs.
The other facts go on the card as tiles. The same headline is not used two days in a row.

Writes <out_dir>/<YYYY-MM-DD>/card.png + post.txt, and latest.json / latest.png / latest.txt.
Nothing is posted anywhere; julian copies the text and card by hand.
"""
import datetime as dt, json, os, sys

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONTS = os.path.join(ROOT, "scripts", "fonts")
SITE = "https://cygon.xyz"
W, H = 1200, 675  # 16:9, shows uncropped in the X timeline
LIMIT = 275  # X allows 280; small margin for counting differences

INK, PANEL, LINE = (5, 5, 6), (14, 15, 18), (51, 54, 62)
FG, MUTED, SILVER = (233, 236, 239), (154, 160, 168), (207, 213, 221)
RED, RED_HI, RED_LO, AMBER = (255, 43, 43), (255, 106, 106), (179, 15, 20), (255, 181, 71)


def font(name, size, weight=None):
    f = ImageFont.truetype(os.path.join(FONTS, name), size)
    if weight:
        f.set_variation_by_name(weight)
    return f


DISPLAY = lambda s: font("ChakraPetch-Bold.ttf", s)
DISPLAY_M = lambda s: font("ChakraPetch-Medium.ttf", s)
MONO = lambda s, w="Regular": font("JetBrainsMono.ttf", s, w)


# ---------- pick the facts ----------

def country_name(D, cc):
    try:
        return json.load(open(os.path.join(ROOT, "scripts", "countries.json")))[cc][2]
    except Exception:
        return cc


def short(s, n):
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1].rstrip(" ,.;:-") + "…"


def clean_vuln_name(k):
    """'Ivanti Connect Secure Missing Authentication ... Vulnerability' -> 'Missing Authentication ...'"""
    name = k.get("name", "")
    for p in (f'{k.get("vendor", "")} {k.get("product", "")}', k.get("vendor", "")):
        if p.strip() and name.lower().startswith(p.lower()):
            name = name[len(p):].strip()
            break
    if name.lower().endswith(" vulnerability"):
        name = name[: -len(" vulnerability")]
    return name or k.get("name", "")


def facts(D, today):
    out = {}
    kev = (D.get("kev") or [None])[0]
    if kev:
        age = (today - dt.date.fromisoformat(kev["added"])).days
        out["kev"] = {
            "id": kev["id"], "what": f'{kev["vendor"]} {kev["product"]}'.strip(), "flaw": clean_vuln_name(kev),
            "added": kev["added"], "age": age, "ransom": kev.get("ransom") == "Known",
        }
    cves = [c for c in D.get("cves") or [] if c.get("score")]
    if cves:
        c = max(cves, key=lambda c: c["score"])
        what = f'{c.get("vendor", "")} {c.get("product", "")}'.strip()
        if what.lower().startswith("n/a") or not what:
            what = c["id"]
        out["cve"] = {"id": c["id"], "what": what, "score": c["score"], "sev": (c.get("sev") or "").upper(), "desc": c.get("desc", "")}
    top = (D.get("topCountries") or [None])[0]
    if top:
        total = D.get("totalIps") or 0
        out["country"] = {"cc": top[0], "name": country_name(D, top[0]), "n": top[1], "total": total,
                          "pct": round(100 * top[1] / total) if total else None}
    hist = D.get("history") or {}
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    rank = {"critical": 3, "major": 2, "minor": 1}
    recent = [i for i in hist.get("timeline", []) if i.get("impact") in rank
              and (i["end"] is None or dt.datetime.fromisoformat(i["end"].replace("Z", "+00:00")) > since)]
    if recent:
        i = max(recent, key=lambda i: (rank[i["impact"]], i["end"] is None, i["start"]))
        out["outage"] = {"svc": i["svc"], "name": " ".join(i["name"].split()), "impact": i["impact"], "ongoing": i["end"] is None}
    elif hist.get("services"):
        out["outage"] = {"svc": None, "n": len(hist["services"])}
    return out


def pick_headline(F, prev):
    """Headline key, skipping yesterday's exact headline so the feed doesn't repeat."""
    order = []
    if "kev" in F and F["kev"]["age"] <= 3:
        order.append("kev")
    if "cve" in F and F["cve"]["score"] >= 9:
        order.append("cve")
    order += [k for k in ("country", "kev", "cve") if k in F and k not in order]
    ident = lambda k: F[k].get("id") or F[k].get("cc")
    for k in order:
        if not (prev and prev.get("headline") == k and prev.get("headlineId") == ident(k)):
            return k, ident(k)
    return order[0], ident(order[0])


# ---------- X post text ----------

def x_len(s):
    """X's weighted length: URLs count 23, most non-Latin characters and emoji count 2."""
    import re
    n = 0
    for part in re.split(r"(https?://\S+)", s):
        if part.startswith("http"):
            n += 23
            continue
        for ch in part:
            o = ord(ch)
            n += 1 if (o <= 0x10FF or 0x2000 <= o <= 0x200D or 0x2010 <= o <= 0x201F or 0x2032 <= o <= 0x2037) else 2
    return n


def post_text(F, head, date):
    d = f"{date:%b} {date.day}"
    lines = {}
    if "kev" in F:
        k = F["kev"]
        when = "today" if k["age"] == 0 else "yesterday" if k["age"] == 1 else f'on {dt.date.fromisoformat(k["added"]):%b} {dt.date.fromisoformat(k["added"]).day}'
        rans = " Linked to ransomware campaigns." if k["ransom"] else ""
        lines["kev"] = (f'🔴 CISA added {k["what"]} {k["id"]} to its Known Exploited list {when}: '
                        f'{short(k["flaw"], 70).lower()}. It is being exploited in the wild, patch now.{rans}')
        lines["kev_s"] = f'🔴 Exploited in the wild: {k["what"]} {k["id"]} (CISA KEV)'
    if "cve" in F:
        c = F["cve"]
        lines["cve"] = f'🧨 Fresh {c["sev"].lower() or "new"} CVE: {c["what"]} {c["id"]}, CVSS {c["score"]}. {short(c["desc"], 110)}'
        lines["cve_s"] = f'🧨 Fresh CVE: {short(c["what"], 40)} {c["id"]}, CVSS {c["score"]}'
    if "country" in F:
        c = F["country"]
        pct = f' ({c["pct"]}% of {c["total"]:,})' if c["pct"] is not None else ""
        lines["country"] = f'🌍 {c["name"]} hosts the most IPs on today\'s blocklists: {c["n"]:,}{pct}.'
        lines["country_s"] = f'🌍 Most flagged IPs today: {c["name"]} ({c["n"]:,})'
    if F.get("outage", {}).get("svc"):
        o = F["outage"]
        lines["outage_s"] = f'⚡ {o["svc"]}: {short(o["name"], 60)} ({o["impact"]}{", ongoing" if o["ongoing"] else ""})'
    elif "outage" in F:
        lines["outage_s"] = f'⚡ No major outages across {F["outage"]["n"]} tracked services'

    if "kev" in F:
        k = F["kev"]
        lines["kev_m"] = f'🔴 CISA confirms {k["what"]} {k["id"]} is being exploited in the wild. Patch now.'
    if "cve" in F:
        c = F["cve"]
        lines["cve_m"] = f'🧨 Fresh {c["sev"].lower() or "new"} CVE: {c["what"]} {c["id"]}, CVSS {c["score"]}. {short(c["desc"], 70)}'
    if "country" in F:
        lines["country_m"] = lines["country"]

    rest = [k + "_s" for k in ("country", "kev", "cve") if k != head and k + "_s" in lines] + (["outage_s"] if "outage_s" in lines else [])
    tail = f"Live tracker 👉 {SITE}\n$CYGON #cybersecurity"
    # keep as many supporting facts as fit, shortening the headline before dropping them
    for drop in range(len(rest) + 1):
        for lead in (head, head + "_m", head + "_s"):
            body = [f"CYGON Threat of the Day · {d}", lines[lead]] + [lines[r] for r in rest[: len(rest) - drop]]
            txt = body[0] + "\n\n" + body[1] + ("\n\n" + "\n".join(body[2:]) if body[2:] else "") + "\n\n" + tail
            if x_len(txt) <= LIMIT:
                return txt
    return f"CYGON Threat of the Day · {d}\n\n{short(lines[head + '_s'], 200)}\n\n{tail}"


# ---------- card ----------

def wrap(draw, text, f, width, max_lines):
    words, lines, cur = text.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if draw.textlength(t, font=f) <= width:
            cur = t
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        while draw.textlength(lines[-1] + "…", font=f) > width and " " in lines[-1]:
            lines[-1] = lines[-1].rsplit(" ", 1)[0]
        lines[-1] = lines[-1].rstrip(" ,.;:-") + "…"
    return lines


def fit(draw, text, maker, width, start, low):
    s = start
    while s > low and draw.textlength(text, font=maker(s)) > width:
        s -= 2
    return maker(s)


def chrome_text(img, xy, text, f, colors):
    """Vertical gradient text, like the logo's chrome / red lettering."""
    d = ImageDraw.Draw(img)
    xy = (int(xy[0]), int(xy[1]))
    l, t, r, b = d.textbbox(xy, text, font=f)
    l, t, r, b = int(l), int(t), int(r) + 1, int(b) + 1
    mask = Image.new("L", img.size, 0)
    ImageDraw.Draw(mask).text(xy, text, font=f, fill=255)
    grad = Image.new("RGB", (1, max(1, b - t)))
    n = len(colors) - 1
    for y in range(b - t):
        p = y / max(1, b - t - 1) * n
        i = min(int(p), n - 1)
        a, c = colors[i], colors[i + 1]
        u = p - i
        grad.putpixel((0, y), tuple(int(a[j] + (c[j] - a[j]) * u) for j in range(3)))
    layer = Image.new("RGB", img.size, 0)
    layer.paste(grad.resize((r - l, b - t)), (l, t))
    glow = mask.filter(ImageFilter.GaussianBlur(14))
    img.paste(Image.new("RGB", img.size, RED), (0, 0), glow.point(lambda v: v * 0.45))
    img.paste(layer, (0, 0), mask)
    return b


def card(F, head, date, path):
    img = Image.new("RGB", (W, H), INK)
    d = ImageDraw.Draw(img)
    # faint grid
    for x in range(0, W, 40):
        d.line([(x, 0), (x, H)], fill=(14, 14, 16))
    for y in range(0, H, 40):
        d.line([(0, y), (W, y)], fill=(14, 14, 16))
    # globe from the logo art on the right, fading into black on the left and bottom
    try:
        og = Image.open(os.path.join(ROOT, "static", "og.jpg")).convert("RGB")
        art = og.crop((320, 0, 880, 440)).resize((560, 440))
        from PIL import ImageChops
        left = Image.linear_gradient("L").rotate(90).resize(art.size).point(lambda v: min(255, int(v * 1.8)))
        down = Image.linear_gradient("L").rotate(180).resize(art.size).point(lambda v: min(255, int(v * 3)))
        mask = ImageChops.multiply(left, down).point(lambda v: int(v * 0.6))
        img.paste(art, (W - 560, 0), mask)
    except Exception as ex:
        print("no art:", ex, file=sys.stderr)
    d = ImageDraw.Draw(img)
    M = 56
    # top bar
    d.rectangle([0, 0, W, 6], fill=RED)
    d.text((M, 40), "THREAT OF THE DAY", font=MONO(20, "Bold"), fill=RED)
    d.text((M, 70), date.strftime("%A %d %B %Y").upper(), font=MONO(18), fill=MUTED)
    tw = d.textlength("CYGON.XYZ", font=DISPLAY(30))
    chrome_text(img, (W - M - tw, 38), "CYGON.XYZ", DISPLAY(30), [(255, 255, 255), SILVER, (120, 126, 134)])
    d = ImageDraw.Draw(img)

    # headline block
    y = 130
    textw = 760
    if head == "kev":
        k = F["kev"]
        tag = "EXPLOITED IN THE WILD · CISA KEV" + (" · RANSOMWARE" if k["ransom"] else "")
        big, sub, foot = k["id"], k["what"], f'{k["flaw"]}. Added {k["added"]}.'
    elif head == "cve":
        c = F["cve"]
        tag = f'NEW {c["sev"] or "HIGH"} CVE · CVSS {c["score"]}'
        big, sub, foot = c["id"], c["what"], c["desc"]
    else:
        c = F["country"]
        tag = "TOP SOURCE OF FLAGGED IPS TODAY"
        big, sub = c["name"], f'{c["n"]:,} flagged IPs' + (f' · {c["pct"]}% of {c["total"]:,}' if c["pct"] is not None else "")
        foot = "Hosts listed on 30+ public blocklists (IPsum), geolocated with DB-IP. Hosting location, not attribution."
    tf = MONO(17, "Bold")
    pw = d.textlength(tag, font=tf) + 28
    d.rounded_rectangle([M, y, M + pw, y + 34], radius=3, outline=RED, width=2, fill=(40, 6, 8))
    d.text((M + 14, y + 7), tag, font=tf, fill=RED_HI)
    y += 54
    bf = fit(d, big, DISPLAY, textw, 92, 44)
    y = chrome_text(img, (M - 2, y), big, bf, [RED_HI, RED, RED_LO]) + 14
    d = ImageDraw.Draw(img)
    sf = DISPLAY_M(40)
    for ln in wrap(d, sub, sf, textw, 1):
        d.text((M, y), ln, font=sf, fill=FG)
        y += 50
    ff = MONO(19)
    for ln in wrap(d, foot, ff, textw, 2):
        d.text((M, y + 2), ln, font=ff, fill=MUTED)
        y += 28

    # three tiles
    tiles = []
    for k in [x for x in ("country", "kev", "cve") if x != head] + ["outage"]:
        if k not in F:
            continue
        if k == "country":
            c = F[k]
            tiles.append(("TOP SOURCE", c["name"], f'{c["n"]:,} flagged IPs'))
        elif k == "kev":
            v = F[k]
            tiles.append(("LATEST EXPLOITED", v["id"], v["what"]))
        elif k == "cve":
            v = F[k]
            tiles.append(("FRESH CVE", f'CVSS {v["score"]}', f'{v["what"]} {v["id"]}'))
        elif F[k].get("svc"):
            o = F[k]
            tiles.append(("OUTAGE WATCH", o["svc"], f'{o["impact"]}{" · ongoing" if o["ongoing"] else ""}: {o["name"]}'))
        else:
            tiles.append(("OUTAGE WATCH", "All clear", f'No major outages, {F[k]["n"]} services'))
    tiles = tiles[:3]
    gap = 18
    tw = (W - 2 * M - gap * (len(tiles) - 1)) / max(1, len(tiles))
    ty, th = H - 66 - 140, 140
    for i, (lab, val, note) in enumerate(tiles):
        x = M + i * (tw + gap)
        d.rectangle([x, ty, x + tw, ty + th], fill=PANEL, outline=LINE)
        d.rectangle([x, ty, x + 4, ty + th], fill=RED if i == 0 else SILVER if i == 1 else AMBER)
        d.text((x + 22, ty + 18), lab, font=MONO(15, "Bold"), fill=MUTED)
        vf = fit(d, val, DISPLAY, tw - 44, 38, 22)
        d.text((x + 22, ty + 42), val, font=vf, fill=FG)
        nf = MONO(15)
        for j, ln in enumerate(wrap(d, note, nf, tw - 44, 2)):
            d.text((x + 22, ty + 92 + j * 22), ln, font=nf, fill=MUTED)

    # footer
    fy = H - 44
    d.text((M, fy), "LIVE CYBER THREAT TRACKER", font=MONO(16, "Bold"), fill=SILVER)
    src = "Sources: CISA KEV · CVE Program · IPsum · public status pages"
    d.text((W - M - d.textlength(src, font=MONO(14)), fy + 2), src, font=MONO(14), fill=(110, 116, 124))
    for i in range(3):  # the logo's three red slashes
        x0 = M + 300 + i * 16
        d.polygon([(x0 + 6, fy + 2), (x0 + 14, fy + 2), (x0 + 8, fy + 18), (x0, fy + 18)], fill=RED)
    img.save(path, optimize=True)


def main():
    data, out = sys.argv[1], sys.argv[2]
    D = json.load(open(data))
    today = dt.datetime.now(dt.timezone.utc).date()
    prev = None
    try:
        prev = json.load(open(os.path.join(out, "latest.json")))
        if prev.get("date") == today.isoformat():  # rerun on the same day: compare with the day before
            prev = prev.get("prev")
    except Exception:
        pass
    F = facts(D, today)
    if not any(k in F for k in ("kev", "cve", "country")):
        sys.exit("no data to build a post from")
    head, hid = pick_headline(F, prev)
    text = post_text(F, head, today)
    day = os.path.join(out, today.isoformat())
    os.makedirs(day, exist_ok=True)
    card(F, head, today, os.path.join(day, "card.png"))
    open(os.path.join(day, "post.txt"), "w").write(text + "\n")
    import shutil
    shutil.copy(os.path.join(day, "card.png"), os.path.join(out, "latest.png"))
    shutil.copy(os.path.join(day, "post.txt"), os.path.join(out, "latest.txt"))
    meta = {"date": today.isoformat(), "headline": head, "headlineId": hid, "text": text, "xLength": x_len(text),
            "facts": F, "snapshot": D.get("snapshot"),
            "prev": {k: prev[k] for k in ("date", "headline", "headlineId")} if prev and "date" in prev else None}
    json.dump(meta, open(os.path.join(out, "latest.json"), "w"), indent=1, ensure_ascii=False)
    json.dump(meta | {"prev": None}, open(os.path.join(day, "meta.json"), "w"), indent=1, ensure_ascii=False)
    print(text)
    print(f"\n[{x_len(text)}/280] headline={head} {hid}")


if __name__ == "__main__":
    main()
