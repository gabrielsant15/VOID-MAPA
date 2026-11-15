
import html
import json
import time
from collections import Counter
 
import plotly.graph_objects as go
import streamlit as st
 
from threat_feeds import (
    CORES_TIPOS,
    obter_api_abuseipdb,
    obter_feed_aberto,
    obter_modo_simulacao,
)
 
# --------------------------------------------------------------------------- #
# 1. Página
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title="VOID MAP | Live Threat Intelligence",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)
 
MODO_FEED = "1. Feed Público Real (Sem Chave)"
MODO_API = "2. API Oficial (AbuseIPDB)"
MODO_SIM = "3. Simulação SOC (Modo Aula)"
 
COR_SEVERIDADE = {"Crítica": "#f43f5e", "Alta": "#fb923c", "Média": "#facc15"}
 
# --------------------------------------------------------------------------- #
# 2. CSS (anti-flash)
# --------------------------------------------------------------------------- #
st.markdown(
    """
    <style>
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background-color: #070b14 !important;
        color: #e2e8f0;
    }
    /* Impede o "apagão" (opacity) que o Streamlit aplica durante o rerun */
    div[data-stale="true"], [data-stale="true"] *, .element-container, .stPlotlyChart {
        opacity: 1 !important;
        transition: none !important;
    }
    [data-testid="stAppViewContainer"] > .main { opacity: 1 !important; transition: none !important; }
    /* Esconde o indicador "Running..." que pisca a cada refresh */
    [data-testid="stStatusWidget"] { visibility: hidden; }
    iframe { background-color: transparent !important; }
    section[data-testid="stSidebar"] { background-color: #0b1120; border-right: 1px solid #1e293b; }
    section[data-testid="stSidebar"] .stButton > button { width: 100%; }
 
    .soc-header {
        background: linear-gradient(90deg, #0f172a 0%, #070b14 100%);
        padding: 15px 20px; border-radius: 8px; border-left: 4px solid #00f2fe; margin-bottom: 15px;
    }
    .soc-title { font-size: 24px; font-weight: 800; letter-spacing: 2px; color: #f8fafc; margin: 0; }
    .soc-subtitle { font-size: 13px; color: #38bdf8; margin: 0; letter-spacing: 1px; }
    .card-panel {
        background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px;
        padding: 15px; margin-bottom: 12px;
    }
    .metric-val { font-size: 26px; font-weight: 700; color: #00f2fe; }
    .metric-lbl { font-size: 12px; color: #94a3b8; text-transform: uppercase; }
    .feed-row {
        font-family: 'Courier New', monospace; font-size: 13px; padding: 6px 10px;
        border-bottom: 1px solid #1e293b; background-color: #0b1120; border-radius: 4px; margin-bottom: 4px;
    }
    .panel-title { font-size: 15px; font-weight: 700; letter-spacing: 1px; margin: 4px 0 10px 0; }
    .bar-row { margin-bottom: 9px; }
    .bar-lbl { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 3px; }
    .bar-bg { background: #1e293b; border-radius: 4px; height: 6px; }
    .bar-fill { height: 6px; border-radius: 4px; }
    </style>
    """,
    unsafe_allow_html=True,
)
 
# --------------------------------------------------------------------------- #
# 3. Estado da sessão
# --------------------------------------------------------------------------- #
for chave, padrao in {
    "historico_eventos": [],
    "total_ataques": 0,
    "lote_atual": [],
    "status_msg": "Inicializando...",
    "ultima_busca": 0.0,
    "assinatura_fonte": None,
    "forcar_busca": False,
}.items():
    st.session_state.setdefault(chave, padrao)
 
# --------------------------------------------------------------------------- #
# 4. Barra lateral
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.markdown("## ⚙️ PAINEL DE CONTROLE")
    st.markdown("---")
 
    modo_selecionado = st.radio(
        "📡 Fonte de Inteligência (3 Modos):",
        [MODO_FEED, MODO_API, MODO_SIM],
        index=0,
    )
 
    api_key_usuario = ""
    if modo_selecionado == MODO_API:
        st.info(
            "🔑 **Quer usar dados oficiais detalhados?**\n\n"
            "Crie uma conta gratuita no AbuseIPDB, gere sua chave na aba *API* e cole abaixo:\n\n"
            "👉 [Cadastrar grátis no AbuseIPDB](https://abuseipdb.com)\n\n"
            "O plano grátis tem limite diário; por isso a lista é guardada em cache por 30 min."
        )
        api_key_usuario = st.text_input(
            "Cole sua API Key aqui:", type="password", placeholder="Ex: a8f9d7e6c5b4..."
        )
    elif modo_selecionado == MODO_FEED:
        st.caption("IPs/países de origem são reais. Alvo e tipo de ataque são ilustrativos.")
 
    st.markdown("---")
    visao_mapa = st.selectbox(
        "🗺️ Projeção do Mapa:",
        ["Globo 3D Espacial (GlobeView)", "Visão Plana 2D"],
        index=0,
    )
    with st.expander("🎥 Câmera inicial do globo"):
        st.caption("Mexer nestes controles reposiciona o globo. Arrastar com o mouse é preservado entre atualizações.")
        rot_lon = st.slider("Longitude central", -180, 180, -45)
        rot_lat = st.slider("Latitude central", -90, 90, 15)
 
    qtd_lote = st.slider("Intensidade de ataques por ciclo:", 5, 30, 15)
    tempo_real = st.toggle("🔴 Ativar Tempo Real (Auto-Refresh)", value=True)
    intervalo = st.slider("Intervalo de atualização (segundos):", 2, 15, 4)
 
    st.markdown("---")
    if st.button("🔄 Atualizar agora"):
        st.session_state.forcar_busca = True
    if st.button("🗑️ Limpar Contadores"):
        st.session_state.historico_eventos = []
        st.session_state.lote_atual = []
        st.session_state.total_ataques = 0
        st.session_state.forcar_busca = True
        st.rerun()
 
 
# --------------------------------------------------------------------------- #
# 5. Funções auxiliares
# --------------------------------------------------------------------------- #
def esc(valor) -> str:
    """Escapa texto vindo de fontes externas antes de injetar em HTML."""
    return html.escape(str(valor))
 
 
def barra_html(rotulo: str, valor: int, maximo: int, cor: str = "#00f2fe") -> str:
    pct = int(valor / maximo * 100) if maximo else 0
    return (
        f'<div class="bar-row"><div class="bar-lbl"><span>{rotulo}</span><b>{valor}</b></div>'
        f'<div class="bar-bg"><div class="bar-fill" style="width:{pct}%;background:{cor}"></div></div></div>'
    )
 
 
def buscar_novos_eventos():
    if modo_selecionado == MODO_FEED:
        return obter_feed_aberto(qtd_lote)
    if modo_selecionado == MODO_API:
        return obter_api_abuseipdb(api_key_usuario, qtd_lote)
    return obter_modo_simulacao(qtd_lote), "Modo Simulação SOC ativo — tráfego sintético em tempo real."
 
 
def construir_mapa(lote: list[dict], antigos: list[dict], globo: bool) -> go.Figure:
    """Mantém SEMPRE o mesmo número/ordem de traces (evita remontar o gráfico = sem flicker)."""
    fig = go.Figure()
    validos = [
        e for e in lote
        if None not in (e["lat_origem"], e["lon_origem"], e["lat_destino"], e["lon_destino"])
    ]
 
    # Trace 0: histórico (pontos de origem tênues)
    fig.add_trace(
        go.Scattergeo(
            lat=[e["lat_origem"] for e in antigos if e["lat_origem"] is not None],
            lon=[e["lon_origem"] for e in antigos if e["lon_origem"] is not None],
            mode="markers",
            marker=dict(size=3, color="#38bdf8", opacity=0.25),
            hoverinfo="skip",
        )
    )
 
    # Um trace de arcos por tipo de ataque (com None separando cada arco)
    for tipo, cor in CORES_TIPOS.items():
        lats, lons = [], []
        for e in validos:
            if e["tipo"] == tipo:
                lats += [e["lat_origem"], e["lat_destino"], None]
                lons += [e["lon_origem"], e["lon_destino"], None]
        fig.add_trace(
            go.Scattergeo(
                lat=lats, lon=lons, mode="lines",
                line=dict(width=2, color=cor), opacity=0.85,
                hoverinfo="skip", connectgaps=False,
            )
        )
 
    # Origens (com hover)
    fig.add_trace(
        go.Scattergeo(
            lat=[e["lat_origem"] for e in validos],
            lon=[e["lon_origem"] for e in validos],
            mode="markers",
            marker=dict(size=6, color=[CORES_TIPOS.get(e["tipo"], "#fff") for e in validos]),
            hovertext=[
                f"<b>{esc(e['tipo'])}</b><br>Origem: {esc(e['origem_nome'])} ({esc(e['ip_origem'])})"
                f"<br>Alvo: {esc(e['destino_nome'])}"
                for e in validos
            ],
            hoverinfo="text",
        )
    )
 
    # Alvos
    fig.add_trace(
        go.Scattergeo(
            lat=[e["lat_destino"] for e in validos],
            lon=[e["lon_destino"] for e in validos],
            mode="markers",
            marker=dict(size=8, color="#ff416c"),
            hovertext=[esc(e["destino_nome"]) for e in validos],
            hoverinfo="text",
        )
    )
 
    projecao = (
        dict(type="orthographic", rotation=dict(lon=rot_lon, lat=rot_lat))
        if globo
        else dict(type="miller")
    )
    # A "revisão" só muda quando o usuário mexe na projeção/câmera da sidebar.
    # Enquanto for a mesma, o Plotly preserva rotação/zoom feitos com o mouse.
    revisao = f"{'globo' if globo else 'plano'}-{rot_lon}-{rot_lat}"
 
    geo = dict(
        uirevision=revisao,
        projection=projecao,
        showland=True, landcolor="#111827",
        showcountries=True, countrycolor="#374151",
        subunitcolor="#1f2937",
        showocean=True, oceancolor="#030712",
        showlakes=True, lakecolor="#030712",
        showframe=False, bgcolor="rgba(0,0,0,0)",
    )
    if not globo:
        geo["lonaxis"] = dict(range=[-180, 180])
 
    fig.update_layout(
        uirevision=revisao,
        geo=geo,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=0, b=0),
        showlegend=False,
        height=520,
        transition=dict(duration=0),
    )
    return fig
 
 
# --------------------------------------------------------------------------- #
# 5b. Componente do mapa (Streamlit >= 1.51: components v2)
#     O gráfico Plotly fica VIVO no navegador; a cada ciclo só chegam dados novos
#     e o JS chama Plotly.react preservando a câmera -> sem piscar, sem resetar.
# --------------------------------------------------------------------------- #
MAPA_JS = """
function carregarPlotly() {
  if (window.Plotly) return Promise.resolve(window.Plotly);
  if (window.__voidPlotlyPromise) return window.__voidPlotlyPromise;
  window.__voidPlotlyPromise = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "https://cdn.jsdelivr.net/npm/plotly.js-dist-min@2.35.2/plotly.min.js";
    s.onload = () => resolve(window.Plotly);
    s.onerror = reject;
    document.head.appendChild(s);
  });
  return window.__voidPlotlyPromise;
}
 
const ICONE_TELA_CHEIA = {
  width: 1000, height: 1000,
  path: "M100 100h300v100H200v200H100z M600 100h300v300H800V200H600z " +
        "M900 600v300H600V800h200V600z M100 600h100v200h200v100H100z",
};
 
function alternarTelaCheia(host) {
  if (document.fullscreenElement) document.exitFullscreen();
  else if (host.requestFullscreen) host.requestFullscreen();
}
 
function resetarCamera(Plotly, host) {
  const i = host.__inicial;
  if (!i) return;
  const upd = { "geo.projection.scale": 1 };
  if (i.globo) {
    upd["geo.projection.rotation.lon"] = i.rot.lon;
    upd["geo.projection.rotation.lat"] = i.rot.lat;
    upd["geo.projection.rotation.roll"] = 0;
  } else {
    upd["geo.lonaxis.range"] = [-180, 180];
    upd["geo.lataxis.range"] = [-90, 90];
  }
  Plotly.relayout(host, upd);
}
 
function desenhar(Plotly, host, d) {
  const layout = d.fig.layout;
  layout.autosize = true;
  delete layout.height;  // a altura vem do container (necessário p/ tela cheia)
  const mesmaCamera = host.__plotted && host.__camRev === d.cam_rev;
 
  if (!mesmaCamera) {
    // guarda a câmera "inicial" para o botão de reset
    const p = layout.geo.projection;
    host.__inicial = {
      globo: p.type === "orthographic",
      rot: p.rotation || { lon: 0, lat: 0 },
    };
  }
 
  if (mesmaCamera) {
    // Reaplica a câmera atual (a que o usuário deixou) por cima do layout novo
    try {
      const g = host._fullLayout.geo;
      if (layout.geo.projection.type === "orthographic") {
        layout.geo.projection.rotation = {
          lon: g.projection.rotation.lon,
          lat: g.projection.rotation.lat,
          roll: g.projection.rotation.roll || 0,
        };
      }
      if (g.projection.scale != null) layout.geo.projection.scale = g.projection.scale;
    } catch (e) { /* mantém o que o uirevision já preserva */ }
  }
 
  host.__camRev = d.cam_rev;
  host.__plotted = true;
  const botoes = [
    { name: "tela-cheia", title: "Tela cheia", icon: ICONE_TELA_CHEIA,
      click: () => alternarTelaCheia(host) },
    { name: "reset-camera", title: "Resetar câmera", icon: Plotly.Icons.home,
      click: () => resetarCamera(Plotly, host) },
  ];
 
  Plotly.react(host, d.fig.data, layout, {
    displaylogo: false,
    displayModeBar: true,
    modeBarButtonsToRemove: ["lasso2d", "select2d", "resetGeo"],
    modeBarButtonsToAdd: botoes,
    scrollZoom: true,
    responsive: true,
  });
}
 
export default function (component) {
  const { data, parentElement } = component;
  let host = parentElement.querySelector("#void-plot");
  if (!host) {
    host = document.createElement("div");
    host.id = "void-plot";
    host.style.cssText = "width:100%;height:520px;";
    parentElement.appendChild(host);
    document.addEventListener("fullscreenchange", () => {
      const cheia = document.fullscreenElement === host;
      host.style.height = cheia ? "100vh" : "520px";
      host.style.background = cheia ? "#070b14" : "transparent";
      setTimeout(() => window.Plotly && window.Plotly.Plots.resize(host), 80);
    });
  }
  carregarPlotly().then((Plotly) => desenhar(Plotly, host, data));
  // Sem função de limpeza de propósito: o gráfico precisa sobreviver às atualizações.
}
"""
 
try:
    mapa_componente = st.components.v2.component(
        "void_map_plotly", js=MAPA_JS, isolate_styles=False
    )
except Exception:  # Streamlit antigo, sem components v2
    mapa_componente = None
 
 
# --------------------------------------------------------------------------- #
# 6. Painel dinâmico
# --------------------------------------------------------------------------- #
@st.fragment(run_every=intervalo if tempo_real else None)
def renderizar_dashboard():
    ss = st.session_state
 
    # Busca desacoplada da renderização: só busca quando o ciclo venceu, a fonte mudou
    # ou o usuário pediu. Mexer em outros widgets NÃO gera ataques novos.
    assinatura = hash((modo_selecionado, api_key_usuario))
    precisa_buscar = (
        not ss.lote_atual
        or ss.forcar_busca
        or ss.assinatura_fonte != assinatura
        or (tempo_real and time.time() - ss.ultima_busca >= intervalo * 0.9)
    )
    if precisa_buscar:
        novos, ss.status_msg = buscar_novos_eventos()
        ss.lote_atual = novos
        ss.total_ataques += len(novos)
        ss.historico_eventos = (novos + ss.historico_eventos)[:200]
        ss.ultima_busca = time.time()
        ss.assinatura_fonte = assinatura
        ss.forcar_busca = False
 
    lote = ss.lote_atual
    historico = ss.historico_eventos
    antigos = historico[len(lote):]
 
    # Cabeçalho
    c1, c2 = st.columns((3, 1))
    with c1:
        st.markdown(
            f"""
            <div class="soc-header">
                <p class="soc-title">🌐 VOID MAP // LIVE THREAT INTELLIGENCE</p>
                <p class="soc-subtitle">STATUS: {esc(ss.status_msg.upper())}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="card-panel" style="text-align:center;">
                <div class="metric-lbl">Ameaças Detectadas na Sessão</div>
                <div class="metric-val">{ss.total_ataques:,}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
 
    col_esq, col_centro, col_dir = st.columns((1.2, 3.2, 1.2))
 
    # Esquerda: alvos mais atacados (um único bloco HTML = menos elementos = menos flicker)
    with col_esq:
        corpo = '<div class="panel-title">🎯 ALVOS MAIS ATACADOS</div>'
        top = Counter(f"{e['destino_flag']} {e['destino_nome']}" for e in historico).most_common(7)
        if top:
            maximo = top[0][1]
            corpo += "".join(barra_html(esc(nome), qtd, maximo, "#38bdf8") for nome, qtd in top)
        st.markdown(corpo, unsafe_allow_html=True)
 
    # Centro: mapa
    with col_centro:
        fig = construir_mapa(lote, antigos, globo="Globo" in visao_mapa)
        if mapa_componente is not None:
            mapa_componente(
                key="void_map_v2",
                data={
                    "fig": json.loads(fig.to_json()),
                    "cam_rev": fig.layout.uirevision,
                },
            )
        else:  # fallback (Streamlit antigo): ainda pode resetar a câmera
            st.plotly_chart(
                fig,
                theme=None,
                config={
                    "displayModeBar": True,
                    "modeBarButtonsToRemove": ["lasso2d", "select2d"],
                    "displaylogo": False,
                    "scrollZoom": True,
                },
                key="void_map_chart",
            )
 
    # Direita: vetores e origens
    with col_dir:
        corpo = '<div class="panel-title">🛡️ VETORES DE ATAQUE</div>'
        tipos = Counter(e["tipo"] for e in historico).most_common(5)
        if tipos:
            maximo = tipos[0][1]
            corpo += "".join(
                barra_html(esc(t), q, maximo, CORES_TIPOS.get(t, "#f43f5e")) for t, q in tipos
            )
        corpo += '<div class="panel-title" style="margin-top:18px;">📍 ORIGENS FREQUENTES</div>'
        origens = Counter(f"{e['origem_flag']} {e['origem_nome']}" for e in historico).most_common(5)
        if origens:
            maximo = origens[0][1]
            corpo += "".join(barra_html(esc(n), q, maximo, "#f43f5e") for n, q in origens)
        st.markdown(corpo, unsafe_allow_html=True)
 
    # Rodapé: feed ao vivo
    linhas = ""
    for ev in lote[:8]:
        cor_sev = COR_SEVERIDADE.get(ev["severidade"], "#f43f5e")
        extra = f" | Score {ev['score']}%" if ev.get("score") is not None else ""
        linhas += f"""
        <div class="feed-row">
            <span style="color:#64748b;">[{esc(ev['hora'])}]</span>
            <span style="color:{cor_sev};font-weight:bold;"> [{esc(ev['severidade'].upper())}]</span>
            <span style="color:#38bdf8;"> {esc(ev['tipo'])}</span> —
            Origem: <b>{esc(ev['origem_flag'])} {esc(ev['origem_nome'])}</b> (<code>{esc(ev['ip_origem'])}</code>)
            ➔ Alvo: <b>{esc(ev['destino_flag'])} {esc(ev['destino_nome'])}</b>
            <span style="color:#94a3b8;">(Porta {ev['porta']} | {esc(ev['fonte'])}{extra})</span>
        </div>"""
    st.markdown(
        '<div class="panel-title">📟 LIVE THREAT FEED (ÚLTIMOS EVENTOS DETECTADOS)</div>' + linhas,
        unsafe_allow_html=True,
    )
 
 
renderizar_dashboard()