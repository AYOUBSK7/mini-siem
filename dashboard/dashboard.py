"""Dashboard du Mini-SIEM (Streamlit).

Il ne parle PAS à la base : il lit l'API FastAPI (/stats et /alertes).
Le dashboard n'a donc pas besoin du mot de passe PostgreSQL.

Lancer (l'API doit tourner) :
    streamlit run dashboard/dashboard.py
"""
import os

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

# Une couleur FIXE par règle (palette testée pour les daltoniens).
# La couleur suit la règle dans tous les graphiques, quel que soit le filtre.
REGLES = ["R1_brute_force", "R2_injection_sql", "R3_xss", "R4_scan", "R5_traversal"]
COULEURS = {
    "R1_brute_force":   "#2a78d6",  # bleu
    "R2_injection_sql": "#eb6834",  # orange
    "R3_xss":           "#1baf7a",  # vert d'eau
    "R4_scan":          "#eda100",  # jaune
    "R5_traversal":     "#e87ba4",  # rose
}
# La gravité est montrée par une icône + un mot, jamais par la couleur seule
ICONES_GRAVITE = {"haute": "🔴 haute", "moyenne": "🟠 moyenne", "faible": "🟡 faible"}
FOND = "#fcfcfb"


# ---------------------------------------------------------------------------
#  Lecture de l'API
# ---------------------------------------------------------------------------
@st.cache_data(ttl=30)   # garde la réponse 30 s pour ne pas appeler l'API à chaque clic
def appeler_api(route, parametres=None):
    reponse = requests.get(f"{API_URL}{route}", params=parametres, timeout=5)
    reponse.raise_for_status()
    return reponse.json()


def mise_en_forme(fig, hauteur=320):
    """Style commun : fond clair, grille discrète, barres fines séparées par 2 px."""
    fig.update_traces(marker_line_color=FOND, marker_line_width=2)
    fig.update_layout(
        height=hauteur, bargap=0.45, plot_bgcolor=FOND, paper_bgcolor=FOND,
        margin=dict(l=10, r=10, t=10, b=10), font=dict(color="#52514e"),
        legend=dict(orientation="h", y=-0.2, title=None),
    )
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(gridcolor="#ebeae6", zeroline=False)
    return fig


# ---------------------------------------------------------------------------
#  Page
# ---------------------------------------------------------------------------
st.set_page_config(page_title="Mini-SIEM", page_icon="🛡️", layout="wide")
st.title("🛡️ Mini-SIEM : attaques détectées dans les journaux nginx")
st.caption("Laboratoire local et éducatif (OWASP Juice Shop). Heures en UTC.")

try:
    stats = appeler_api("/stats")
except requests.HTTPError as erreur:
    # L'API répond, mais avec une erreur (ex : 503 tables absentes) : on affiche son message
    st.error(erreur.response.json().get("erreur", str(erreur)))
    st.stop()
except requests.RequestException as erreur:
    st.error(f"Impossible de joindre l'API ({API_URL}). Est-elle lancée ?\n\n{erreur}")
    st.stop()

if st.button("🔄 Rafraîchir"):
    st.cache_data.clear()
    st.rerun()

if stats["nb_alertes"] == 0:
    st.info("Aucune alerte. Lancer attack_sim.py, puis etl.py et detect.py.")
    st.stop()

# --- Chiffres clés ---------------------------------------------------------
nb_hautes = sum(g["nb"] for g in stats["alertes_par_gravite"] if g["gravite"] == "haute")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Requêtes analysées", stats["nb_requetes"])
col2.metric("Adresses IP", stats["nb_ip"])
col3.metric("Alertes", stats["nb_alertes"])
col4.metric("🔴 Alertes hautes", nb_hautes)

# --- Alertes par type et par heure -----------------------------------------
gauche, droite = st.columns(2)

with gauche:
    st.subheader("Alertes par type")
    df_regle = pd.DataFrame(stats["alertes_par_regle"])
    fig = px.bar(df_regle, x="nb", y="regle", orientation="h", text="nb",
                 color="regle", color_discrete_map=COULEURS,
                 category_orders={"regle": REGLES},
                 labels={"nb": "Nombre d'alertes", "regle": ""},
                 hover_data={"categorie_owasp": True, "regle": False})
    fig.update_traces(textposition="outside", textfont_color="#52514e", cliponaxis=False)
    fig.update_xaxes(range=[0, df_regle["nb"].max() * 1.15])   # place pour le chiffre au bout
    st.plotly_chart(mise_en_forme(fig).update_layout(showlegend=False), width="stretch")

with droite:
    st.subheader("Alertes par heure")
    df_heure = pd.DataFrame(stats["alertes_par_heure"])
    df_heure["heure"] = pd.to_datetime(df_heure["heure"]).dt.strftime("%d/%m %Hh")
    fig = px.bar(df_heure, x="heure", y="nb", color="regle",
                 color_discrete_map=COULEURS, category_orders={"regle": REGLES},
                 labels={"nb": "Nombre d'alertes", "heure": "", "regle": "Règle"})
    st.plotly_chart(mise_en_forme(fig), width="stretch")
    with st.expander("Voir les données"):
        st.dataframe(df_heure.pivot_table(index="heure", columns="regle", values="nb",
                                          fill_value=0), width="stretch")

# --- Top 10 des IP ---------------------------------------------------------
st.subheader("Top 10 des IP qui déclenchent le plus d'alertes")
df_ip = pd.DataFrame(stats["top_ip"])
st.dataframe(
    df_ip, hide_index=True, width="stretch",
    column_config={
        "ip": "Adresse IP",
        "nb_alertes": st.column_config.ProgressColumn(
            "Alertes", format="%d", min_value=0, max_value=int(df_ip["nb_alertes"].max())),
        "nb_requetes": "Requêtes envoyées",
        "regles": "Règles déclenchées",
    },
)

# --- Dernières alertes, avec filtres ---------------------------------------
st.subheader("Dernières alertes")
f1, f2, f3 = st.columns(3)
regle_choisie = f1.selectbox("Règle", ["toutes"] + REGLES)
gravite_choisie = f2.selectbox("Gravité", ["toutes", "haute", "moyenne", "faible"])
limite = f3.slider("Nombre d'alertes", 10, 500, 50, step=10)

# Les filtres sont envoyés à l'API, qui fait la requête SQL (paramétrée)
parametres = {"limite": limite}
if regle_choisie != "toutes":
    parametres["regle"] = regle_choisie
if gravite_choisie != "toutes":
    parametres["gravite"] = gravite_choisie

df_alertes = pd.DataFrame(appeler_api("/alertes", parametres))
if df_alertes.empty:
    st.write("Aucune alerte pour ces filtres.")
else:
    df_alertes["gravite"] = df_alertes["gravite"].map(ICONES_GRAVITE)
    df_alertes["horodatage"] = pd.to_datetime(df_alertes["horodatage"]).dt.strftime("%d/%m %H:%M:%S")
    st.dataframe(
        df_alertes[["horodatage", "regle", "gravite", "ip", "categorie_owasp", "preuve"]],
        hide_index=True, width="stretch",
        column_config={"horodatage": "Heure (UTC)", "regle": "Règle", "gravite": "Gravité",
                       "ip": "IP", "categorie_owasp": "OWASP", "preuve": "Preuve"},
    )
