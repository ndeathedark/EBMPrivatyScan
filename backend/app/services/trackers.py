"""Lista documentada de patrones de recursos de terceros (RF08).

Limitación declarada: la detección se basa SOLO en esta lista. Un recurso que no
coincida no se clasifica como rastreador, aunque pueda serlo. Actualizar la lista
es parte del mantenimiento del sistema (ver LIST_VERSION).
"""
LIST_VERSION = "2026-11"

# Finalidades probables
ANALITICA = "analítica"
PUBLICIDAD = "publicidad"
REMARKETING = "publicidad / remarketing"
SESIONES = "grabación de sesiones / analítica"
MARKETING = "marketing / analítica"

# Proveedores
GOOGLE_ANALYTICS = "Google Analytics"
GOOGLE_ADS = "Google Ads"
META_PIXEL = "Meta Pixel"
MS_CLARITY = "Microsoft Clarity"
MS_ADS = "Microsoft Ads"
LINKEDIN = "LinkedIn Insight"
X_ADS = "X (Twitter) Ads"
CRITEO = "Criteo"
HUBSPOT = "HubSpot"

# dominio (o sufijo) -> (proveedor, finalidad probable)
TRACKER_PATTERNS: dict[str, tuple[str, str]] = {
    "google-analytics.com": (GOOGLE_ANALYTICS, ANALITICA),
    "analytics.google.com": (GOOGLE_ANALYTICS, ANALITICA),
    "googletagmanager.com": ("Google Tag Manager", "gestor de etiquetas"),
    "doubleclick.net": ("Google Ads / DoubleClick", PUBLICIDAD),
    "googleadservices.com": (GOOGLE_ADS, REMARKETING),
    "googlesyndication.com": ("Google AdSense", PUBLICIDAD),
    "adservice.google.com": (GOOGLE_ADS, PUBLICIDAD),
    "connect.facebook.net": (META_PIXEL, REMARKETING),
    "facebook.com/tr": (META_PIXEL, REMARKETING),
    "hotjar.com": ("Hotjar", SESIONES),
    "clarity.ms": (MS_CLARITY, SESIONES),
    "bat.bing.com": (MS_ADS, REMARKETING),
    "analytics.tiktok.com": ("TikTok Pixel", REMARKETING),
    "snap.licdn.com": (LINKEDIN, REMARKETING),
    "px.ads.linkedin.com": (LINKEDIN, REMARKETING),
    "static.ads-twitter.com": (X_ADS, PUBLICIDAD),
    "analytics.twitter.com": (X_ADS, PUBLICIDAD),
    "ct.pinterest.com": ("Pinterest Tag", PUBLICIDAD),
    "mc.yandex.ru": ("Yandex Metrica", ANALITICA),
    "cdn.segment.com": ("Segment", ANALITICA),
    "mixpanel.com": ("Mixpanel", ANALITICA),
    "amplitude.com": ("Amplitude", ANALITICA),
    "taboola.com": ("Taboola", PUBLICIDAD),
    "outbrain.com": ("Outbrain", PUBLICIDAD),
    "criteo.com": (CRITEO, REMARKETING),
    "criteo.net": (CRITEO, REMARKETING),
    "scorecardresearch.com": ("Comscore", "medición de audiencias"),
    "quantserve.com": ("Quantcast", PUBLICIDAD),
    "hubspot.com": (HUBSPOT, MARKETING),
    "hs-scripts.com": (HUBSPOT, MARKETING),
    "hs-analytics.net": (HUBSPOT, MARKETING),
}

# Cookies de seguimiento conocidas (prefijo -> proveedor)
TRACKING_COOKIE_PREFIXES: dict[str, str] = {
    "_ga": GOOGLE_ANALYTICS,
    "_gid": GOOGLE_ANALYTICS,
    "_gat": GOOGLE_ANALYTICS,
    "_gcl_": GOOGLE_ADS,
    "_fbp": META_PIXEL,
    "_fbc": META_PIXEL,
    "_hj": "Hotjar",
    "_clck": MS_CLARITY,
    "_clsk": MS_CLARITY,
    "_uetsid": MS_ADS,
    "_uetvid": MS_ADS,
    "_ttp": "TikTok Pixel",
    "li_": "LinkedIn",
    "_pin_unauth": "Pinterest",
    "hubspotutk": HUBSPOT,
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
