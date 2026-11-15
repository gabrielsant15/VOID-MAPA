"""Fontes de dados do VOID MAP.

Três modos:
  1. Feed público real  -> IPs de listas públicas (blocklist.de / Feodo Tracker),
                           geolocalizados via ip-api.com (origens REAIS).
  2. AbuseIPDB          -> blacklist oficial (precisa de chave gratuita).
  3. Simulação SOC      -> tráfego sintético (IPs de faixas reservadas p/ documentação).

Obs.: nos modos 1 e 2 o IP/país de origem é real, mas o alvo e o "tipo de ataque"
são ilustrativos (as listas públicas não informam quem foi atacado).
"""
from __future__ import annotations

import ipaddress
import random
from datetime import datetime

import requests
import streamlit as st

HEADERS = {"User-Agent": "VOID-MAP/2.0 (dashboard educacional de ameaças)"}
TIMEOUT = 10


class ErroFeed(Exception):
    """Falha ao obter dados de um feed (não é guardada no cache)."""

    def __init__(self, mensagem: str, codigo: int | None = None):
        super().__init__(mensagem)
        self.codigo = codigo


# --------------------------------------------------------------------------- #
# Países (centroides aproximados)
# --------------------------------------------------------------------------- #
_PAISES_RAW = [
    ("Brasil", "BR", -14.2350, -51.9253),
    ("Estados Unidos", "US", 37.0902, -95.7129),
    ("China", "CN", 35.8617, 104.1954),
    ("Rússia", "RU", 61.5240, 105.3188),
    ("Alemanha", "DE", 51.1657, 10.4515),
    ("Reino Unido", "GB", 55.3781, -3.4360),
    ("Índia", "IN", 20.5937, 78.9629),
    ("Japão", "JP", 36.2048, 138.2529),
    ("França", "FR", 46.2276, 2.2137),
    ("Canadá", "CA", 56.1304, -106.3468),
    ("Coreia do Sul", "KR", 35.9078, 127.7669),
    ("Holanda", "NL", 52.1326, 5.2913),
    ("Austrália", "AU", -25.2744, 133.7751),
    ("Argentina", "AR", -38.4161, -63.6167),
    ("México", "MX", 23.6345, -102.5528),
    ("Itália", "IT", 41.8719, 12.5674),
    ("Espanha", "ES", 40.4637, -3.7492),
    ("Turquia", "TR", 38.9637, 35.2433),
    ("Irã", "IR", 32.4279, 53.6880),
    ("Indonésia", "ID", -0.7893, 113.9213),
    ("Vietnã", "VN", 14.0583, 108.2772),
    ("África do Sul", "ZA", -30.5595, 22.9375),
    ("Ucrânia", "UA", 48.3794, 31.1656),
    ("Polônia", "PL", 51.9194, 19.1451),
    ("Singapura", "SG", 1.3521, 103.8198),
    ("Egito", "EG", 26.8206, 30.8025),
    ("Nigéria", "NG", 9.0820, 8.6753),
    ("Arábia Saudita", "SA", 23.8859, 45.0792),
]


def codigo_para_flag(codigo: str | None) -> str:
    """Converte 'BR' em 🇧🇷 usando indicadores regionais Unicode."""
    if not codigo or len(codigo) != 2 or not codigo.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in codigo.upper())


PAISES = [
    {"nome": n, "codigo": c, "flag": codigo_para_flag(c), "lat": la, "lon": lo}
    for n, c, la, lo in _PAISES_RAW
]
MAPA_CODIGO_PAIS = {p["codigo"]: p for p in PAISES}

TIPO_ABUSEIPDB = "AbuseIPDB Blacklist"

TIPOS_ATAQUE = [
    {"tipo": "DDoS Volumetric", "porta": 80, "cor": "#ff0055", "sev": "Crítica"},
    {"tipo": "Ransomware C2", "porta": 445, "cor": "#ff4500", "sev": "Crítica"},
    {"tipo": "SSH Brute Force", "porta": 22, "cor": "#ffd700", "sev": "Média"},
    {"tipo": "SQL Injection", "porta": 443, "cor": "#a855f7", "sev": "Alta"},
    {"tipo": "Botnet Malware", "porta": 8080, "cor": "#ec4899", "sev": "Alta"},
]

# Cor de cada tipo (usada pelo mapa; ordem fixa = nº de traces estável = sem flicker)
CORES_TIPOS = {t["tipo"]: t["cor"] for t in TIPOS_ATAQUE}
CORES_TIPOS[TIPO_ABUSEIPDB] = "#00f2fe"


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def _agora() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _eh_ipv4(texto: str) -> bool:
    try:
        ipaddress.IPv4Address(texto)
        return True
    except ValueError:
        return False


def _ip_ficticio() -> str:
    """IP de faixas reservadas para documentação (RFC 5737): nunca é um host real."""
    base = random.choice(["192.0.2", "198.51.100", "203.0.113"])
    return f"{base}.{random.randint(1, 254)}"


def _montar_evento(
    *,
    ip: str,
    origem_nome: str,
    origem_flag: str,
    lat_origem: float,
    lon_origem: float,
    destino: dict,
    ameaca: dict,
    fonte: str,
    tipo: str | None = None,
    severidade: str | None = None,
    cor: str | None = None,
    score: int | None = None,
    jitter_destino: float = 1.5,
) -> dict:
    return {
        "hora": _agora(),
        "ip_origem": ip,
        "origem_nome": origem_nome,
        "origem_flag": origem_flag,
        "lat_origem": lat_origem,
        "lon_origem": lon_origem,
        "destino_nome": destino["nome"],
        "destino_flag": destino["flag"],
        "lat_destino": destino["lat"] + random.uniform(-jitter_destino, jitter_destino),
        "lon_destino": destino["lon"] + random.uniform(-jitter_destino, jitter_destino),
        "tipo": tipo or ameaca["tipo"],
        "porta": ameaca["porta"],
        "severidade": severidade or ameaca["sev"],
        "cor": cor or ameaca["cor"],
        "score": score,
        "fonte": fonte,
    }


# --------------------------------------------------------------------------- #
# Modo 3: Simulação
# --------------------------------------------------------------------------- #
def obter_modo_simulacao(qtd: int = 18) -> list[dict]:
    eventos = []
    for _ in range(qtd):
        origem, destino = random.sample(PAISES, 2)
        eventos.append(
            _montar_evento(
                ip=_ip_ficticio(),
                origem_nome=origem["nome"],
                origem_flag=origem["flag"],
                lat_origem=origem["lat"] + random.uniform(-2.5, 2.5),
                lon_origem=origem["lon"] + random.uniform(-2.5, 2.5),
                destino=destino,
                ameaca=random.choice(TIPOS_ATAQUE),
                fonte="Simulação SOC",
                jitter_destino=2.0,
            )
        )
    return eventos


# --------------------------------------------------------------------------- #
# Modo 1: Feed público real
# --------------------------------------------------------------------------- #
@st.cache_data(ttl=900, show_spinner=False)
def _baixar_lista_ips() -> tuple[str, list[str]]:
    """Baixa a lista de IPs maliciosos (cache de 15 min). Exceções não são cacheadas."""
    fontes = [
        ("blocklist.de", "https://lists.blocklist.de/lists/all.txt"),
        ("Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ]
    for nome, url in fontes:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            resp.raise_for_status()
        except requests.RequestException:
            continue
        ips = [ln.strip() for ln in resp.text.splitlines() if _eh_ipv4(ln.strip())]
        if ips:
            return nome, ips
    raise ErroFeed("Nenhum feed público respondeu.")


@st.cache_data(ttl=120, show_spinner=False)
def _lote_geolocalizado() -> tuple[str, list[dict]]:
    """Sorteia até 100 IPs e geolocaliza em UMA chamada (cache de 2 min).

    ip-api.com (plano grátis): HTTP apenas, ~15 requisições/min por IP, uso não comercial.
    """
    fonte, ips = _baixar_lista_ips()
    amostra = random.sample(ips, min(100, len(ips)))
    try:
        resp = requests.post(
            "http://ip-api.com/batch",
            params={"fields": "status,country,countryCode,lat,lon,query", "lang": "pt-BR"},
            json=amostra,
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        itens = [
            i
            for i in resp.json()
            if i.get("status") == "success"
            and i.get("lat") is not None
            and i.get("lon") is not None
        ]
    except (requests.RequestException, ValueError) as exc:
        raise ErroFeed(f"Falha na geolocalização: {exc}") from exc
    if not itens:
        raise ErroFeed("Geolocalização sem resultados.")
    return fonte, itens


def obter_feed_aberto(qtd: int = 15) -> tuple[list[dict], str]:
    try:
        fonte, itens = _lote_geolocalizado()
    except Exception:
        return obter_modo_simulacao(qtd), "Feed indisponível/timeout — usando Modo Simulação."

    eventos = []
    for item in random.sample(itens, min(qtd, len(itens))):
        ameaca = TIPOS_ATAQUE[4] if fonte == "Feodo Tracker" else random.choice(TIPOS_ATAQUE)
        eventos.append(
            _montar_evento(
                ip=item["query"],
                origem_nome=item.get("country") or "Desconhecido",
                origem_flag=codigo_para_flag(item.get("countryCode")),
                lat_origem=item["lat"],
                lon_origem=item["lon"],
                destino=random.choice(PAISES),
                ameaca=ameaca,
                fonte=f"Feed Real · {fonte}",
            )
        )
    return eventos, f"Conectado ao feed público ({fonte}) — origens reais, alvos ilustrativos"


# --------------------------------------------------------------------------- #
# Modo 2: AbuseIPDB
# --------------------------------------------------------------------------- #
@st.cache_data(ttl=1800, show_spinner=False)
def _baixar_blacklist_abuseipdb(api_key: str) -> list[dict]:
    """Uma chamada a cada 30 min: o plano grátis permite só ~5 consultas/dia na blacklist."""
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"confidenceMinimum": 90, "limit": 500},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ErroFeed(f"Erro de rede: {exc}") from exc

    if resp.status_code != 200:
        raise ErroFeed("Resposta inesperada da API.", codigo=resp.status_code)
    dados = resp.json().get("data", [])
    if not dados:
        raise ErroFeed("A API não retornou dados.")
    return dados


def obter_api_abuseipdb(api_key: str, qtd: int = 18) -> tuple[list[dict], str]:
    api_key = (api_key or "").strip()
    if len(api_key) < 10:
        return obter_modo_simulacao(qtd), "Insira uma API Key válida do AbuseIPDB na barra lateral."

    try:
        lista = _baixar_blacklist_abuseipdb(api_key)
    except ErroFeed as exc:
        if exc.codigo in (401, 403):
            msg = "Chave API inválida ou sem permissão — usando Modo Simulação."
        elif exc.codigo == 429:
            msg = "Limite diário do AbuseIPDB atingido — usando Modo Simulação."
        else:
            msg = "Erro ao consultar AbuseIPDB — usando Modo Simulação."
        return obter_modo_simulacao(qtd), msg

    conhecidos = [i for i in lista if i.get("countryCode") in MAPA_CODIGO_PAIS]
    if not conhecidos:
        return obter_modo_simulacao(qtd), "AbuseIPDB sem países mapeáveis — usando Modo Simulação."

    eventos = []
    for item in random.sample(conhecidos, min(qtd, len(conhecidos))):
        origem = MAPA_CODIGO_PAIS[item["countryCode"]]
        destino = random.choice([p for p in PAISES if p["codigo"] != origem["codigo"]])
        ameaca = random.choice(TIPOS_ATAQUE)
        eventos.append(
            _montar_evento(
                ip=item.get("ipAddress", "?"),
                origem_nome=origem["nome"],
                origem_flag=origem["flag"],
                lat_origem=origem["lat"] + random.uniform(-2.0, 2.0),
                lon_origem=origem["lon"] + random.uniform(-2.0, 2.0),
                destino=destino,
                ameaca=ameaca,
                fonte="AbuseIPDB API",
                tipo=TIPO_ABUSEIPDB,
                severidade="Crítica",
                cor=CORES_TIPOS[TIPO_ABUSEIPDB],
                score=item.get("abuseConfidenceScore"),
                jitter_destino=2.0,
            )
        )
    return eventos, "Conectado à API oficial AbuseIPDB (cache de 30 min) — alvos ilustrativos"
