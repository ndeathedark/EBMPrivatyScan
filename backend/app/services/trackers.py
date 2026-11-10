"""Lista documentada de patrones de recursos de terceros (RF08).

Limitación declarada: la detección se basa SOLO en esta lista. Un recurso que no
coincida no se clasifica como rastreador, aunque pueda serlo. Actualizar la lista
es parte del mantenimiento del sistema (ver LIST_VERSION).
"""
LIST_VERSION = "2026-11"

# dominio (o sufijo) -> (proveedor, finalidad probable)
TRACKER_PATTERNS: dict[str, tuple[str, str]] = {
    "google-analytics.com": ("Google Analytics", "analítica"),
    "analytics.google.com": ("Google Analytics", "analítica"),
    "googletagmanager.com": ("Google Tag Manager", "gestor de etiquetas"),
    "doubleclick.net": ("Google Ads / DoubleClick", "publicidad"),
    "googleadservices.com": ("Google Ads", "publicidad / remarketing"),
    "googlesyndication.com": ("Google AdSense", "publicidad"),
    "adservice.google.com": ("Google Ads", "publicidad"),
    "connect.facebook.net": ("Meta Pixel", "publicidad / remarketing"),
    "facebook.com/tr": ("Meta Pixel", "publicidad / remarketing"),
    "hotjar.com": ("Hotjar", "grabación de sesiones / analítica"),
    "clarity.ms": ("Microsoft Clarity", "grabación de sesiones / analítica"),
    "bat.bing.com": ("Microsoft Ads", "publicidad / remarketing"),
    "analytics.tiktok.com": ("TikTok Pixel", "publicidad / remarketing"),
    "snap.licdn.com": ("LinkedIn Insight", "publicidad / remarketing"),
    "px.ads.linkedin.com": ("LinkedIn Insight", "publicidad / remarketing"),
    "static.ads-twitter.com": ("X (Twitter) Ads", "publicidad"),
    "analytics.twitter.com": ("X (Twitter) Ads", "publicidad"),
    "ct.pinterest.com": ("Pinterest Tag", "publicidad"),
    "mc.yandex.ru": ("Yandex Metrica", "analítica"),
    "cdn.segment.com": ("Segment", "analítica"),
    "mixpanel.com": ("Mixpanel", "analítica"),
    "amplitude.com": ("Amplitude", "analítica"),
    "taboola.com": ("Taboola", "publicidad"),
    "outbrain.com": ("Outbrain", "publicidad"),
    "criteo.com": ("Criteo", "publicidad / remarketing"),
    "criteo.net": ("Criteo", "publicidad / remarketing"),
    "scorecardresearch.com": ("Comscore", "medición de audiencias"),
    "quantserve.com": ("Quantcast", "publicidad"),
    "hubspot.com": ("HubSpot", "marketing / analítica"),
    "hs-scripts.com": ("HubSpot", "marketing / analítica"),
    "hs-analytics.net": ("HubSpot", "marketing / analítica"),
}

# Cookies de seguimiento conocidas (prefijo -> proveedor)
TRACKING_COOKIE_PREFIXES: dict[str, str] = {
    "_ga": "Google Analytics",
    "_gid": "Google Analytics",
    "_gat": "Google Analytics",
    "_gcl_": "Google Ads",
    "_fbp": "Meta Pixel",
    "_fbc": "Meta Pixel",
    "_hj": "Hotjar",
    "_clck": "Microsoft Clarity",
    "_clsk": "Microsoft Clarity",
    "_uetsid": "Microsoft Ads",
    "_uetvid": "Microsoft Ads",
    "_ttp": "TikTok Pixel",
    "li_": "LinkedIn",
    "_pin_unauth": "Pinterest",
    "hubspotutk": "HubSpot",
    "_ym_": "Yandex Metrica",
}


def match_tracker(url: str) -> tuple[str, str] | None:
    lowered = url.lower().split("://", 1)[-1]
    host = lowered.split("/", 1)[0].split(":", 1)[0]
    for pattern, info in TRACKER_PATTERNS.items():
        if "/" in pattern:
            if lowered.startswith(pattern) or lowered.startswith("www." + pattern):
                return info
        elif host == pattern or host.endswith("." + pattern):
            return info
    return None


def match_tracking_cookie(name: str) -> str | None:
    for prefix, provider in TRACKING_COOKIE_PREFIXES.items():
        if name.startswith(prefix):
            return provider
    return None
