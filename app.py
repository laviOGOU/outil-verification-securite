import hashlib
import logging
import re
import sqlite3
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests
import streamlit as st

# ==========================================
# 1. CONFIGURATION & LOGGING
# ==========================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CyberShield")

DB_PATH = "cybershield_data.db"

# ==========================================
# 2. COUCHE DE PERSISTANCE (SQLITE)
# ==========================================


def init_db() -> None:
    """Initialise la base de données SQLite pour la télémétrie."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    detail TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    metric_key TEXT PRIMARY KEY,
                    metric_value INTEGER DEFAULT 0
                )
            """)
            keys = [
                "visites_totales",
                "tests_mdp",
                "mdp_forts",
                "mdp_moyens",
                "mdp_faibles",
                "mdp_compromis",
                "tests_email",
                "emails_compromis",
            ]
            for key in keys:
                cursor.execute(
                    "INSERT OR IGNORE INTO metrics (metric_key, metric_value) VALUES (?, 0)",
                    (key,),
                )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(
            f"Erreur d'initialisation de la base de données : {str(e)}"
        )


def increment_metric(key: str, amount: int = 1) -> None:
    """Incrémente une valeur métrique spécifique en base de données."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE metrics SET metric_value = metric_value + ? WHERE metric_key = ?",
                (amount, key),
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(
            f"Erreur lors de la mise à jour de la métrique {key} : {str(e)}"
        )


def get_all_metrics() -> Dict[str, int]:
    """Récupère l'ensemble des métriques enregistrées."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT metric_key, metric_value FROM metrics")
            return dict(cursor.fetchall())
    except sqlite3.Error as e:
        logger.error(f"Erreur lors de la lecture des métriques : {str(e)}")
        return {}


def log_event(event_type: str, detail: str = "") -> None:
    """Enregistre un événement journalisé dans la table de télémétrie."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO telemetry (event_type, detail) VALUES (?, ?)",
                (event_type, detail),
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(
            f"Erreur lors de l'enregistrement de l'événement : {str(e)}"
        )


init_db()

# ==========================================
# 3. SERVICES D'AUDIT DE SÉCURITÉ
# ==========================================


@dataclass
class PasswordCriterion:
    description: str
    is_met: bool
    recommendation: str


class PasswordSecurityEvaluator:

    @staticmethod
    def evaluate(password: str) -> Tuple[str, float, List[PasswordCriterion]]:
        criteria = [
            PasswordCriterion(
                "Longueur d'au moins 12 caractères",
                len(password) >= 12,
                "Rallongez le mot de passe : utilisez au moins 12 à 16 caractères (ou une passphrase de plusieurs mots).",
            ),
            PasswordCriterion(
                "Contient des lettres majuscules (A-Z)",
                bool(re.search(r"[A-Z]", password)),
                "Insérez au moins une lettre majuscule à un endroit imprévisible.",
            ),
            PasswordCriterion(
                "Contient des lettres minuscules (a-z)",
                bool(re.search(r"[a-z]", password)),
                "Incorporez des lettres minuscules.",
            ),
            PasswordCriterion(
                "Contient des chiffres (0-9)",
                bool(re.search(r"[0-9]", password)),
                "Ajoutez un ou plusieurs chiffres au sein du mot de passe.",
            ),
            PasswordCriterion(
                "Contient des symboles spéciaux (!@#$%...)",
                bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
                "Ajoutez des caractères spéciaux (ex: @, #, !, $, %).",
            ),
        ]

        score = sum(1 for c in criteria if c.is_met)
        percentage = (score / len(criteria)) * 100

        if score >= 5:
            level = "Fort"
        elif score >= 3:
            level = "Moyen"
        else:
            level = "Faible"

        return level, percentage, criteria

    @staticmethod
    def check_hibp_pwned(password: str) -> Optional[int]:
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(
                url,
                headers={"User-Agent": "CyberShield-Audit-Tool"},
                timeout=5,
            )
            if response.status_code == 200:
                for line in response.text.splitlines():
                    h, count = line.split(":")
                    if h == suffix:
                        return int(count)
                return 0
            return None
        except requests.RequestException as e:
            logger.error(f"Erreur API HIBP : {str(e)}")
            return None


class EmailBreachEvaluator:

    @staticmethod
    def check_breaches(email: str) -> Tuple[Optional[bool], List[str]]:
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        try:
            response = requests.get(
                url,
                headers={"User-Agent": "CyberShield-Audit-Tool"},
                timeout=5,
            )
            if response.status_code == 200:
                data = response.json()
                if "breaches" in data and data["breaches"]:
                    return True, data["breaches"][0]
                return False, []
            elif response.status_code == 404:
                return False, []
            return None, []
        except requests.RequestException as e:
            logger.error(f"Erreur API Breach Check : {str(e)}")
            return None, []


# ==========================================
# 4. INTERFACE UTILISATEUR (STREAMLIT)
# ==========================================

st.set_page_config(
    page_title="CyberShield Professional Edition",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown(
    """
    <style>
        .stApp {
            background-color: #0A0E17;
            color: #C9D1D9;
        }
        
        .title-header {
            font-family: 'Inter', sans-serif;
            font-size: 2.8rem;
            font-weight: 800;
            background: linear-gradient(90deg, #38BDF8 0%, #818CF8 50%, #C084FC 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-align: center;
            margin-bottom: 0.2rem;
            letter-spacing: -0.02em;
        }
        
        .subtitle-header {
            text-align: center;
            color: #6B7280;
            font-size: 1.1rem;
            font-weight: 400;
            margin-bottom: 1.5rem;
        }

        .welcome-card {
            background: linear-gradient(135deg, #161B22 0%, #1F2937 100%);
            border: 1px solid #30363D;
            border-left: 5px solid #818CF8;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 2rem;
            text-align: center;
        }

        .welcome-title {
            font-size: 1.3rem;
            font-weight: 700;
            color: #F3F4F6;
            margin-bottom: 8px;
        }

        .welcome-text {
            color: #9CA3AF;
            font-size: 0.95rem;
            margin-bottom: 0;
        }
        
        /* Expansion des onglets sur toute la largeur */
        div[data-baseweb="tab-list"] {
            width: 100% !important;
            display: flex !important;
            justify-content: space-between !important;
        }

        div[data-baseweb="tab"] {
            flex: 1 !important;
            text-align: center !important;
            justify-content: center !important;
        }
        
        .recom-box {
            background-color: #161B22;
            border: 1px solid #30363D;
            border-left: 4px solid #38BDF8;
            border-radius: 8px;
            padding: 16px;
            margin-top: 15px;
        }
        
        .metric-card {
            background: #161B22;
            border: 1px solid #30363D;
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }
        
        .metric-value {
            font-size: 2rem;
            font-weight: 700;
            color: #58A6FF;
        }
        
        .metric-label {
            font-size: 0.85rem;
            color: #8B949E;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }

        .news-card {
            background: #161B22;
            border: 1px solid #30363D;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 12px;
        }

        .news-title {
            font-weight: 700;
            color: #F87171;
            font-size: 0.9rem;
        }

        .news-details {
            font-size: 0.8rem;
            color: #9CA3AF;
            margin-top: 4px;
        }
    </style>
""",
    unsafe_allow_html=True,
)

if "session_active" not in st.session_state:
    st.session_state["session_active"] = True
    increment_metric("visites_totales")
    user_agent = st.context.headers.get("User-Agent", "Unknown")
    log_event("VISIT", f"User-Agent: {user_agent}")

st.markdown(
    '<div class="title-header">🛡️ CYBERSHIELD SECURITY AUDITOR</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="subtitle-header">Plateforme d\'évaluation des vulnérabilités et télémétrie anonymisée</div>',
    unsafe_allow_html=True,
)

# Message d'accueil incitatif
st.markdown(
    """
    <div class="welcome-card">
        <div class="welcome-title">👋 Bienvenue sur votre centre de contrôle de sécurité</div>
        <p class="welcome-text">
            Sélectionnez un onglet ci-dessous pour démarrer : 
            <b>🔑 Valider la robustesse d'un mot de passe</b>, 
            <b>📧 Vérifier si votre e-mail a été compromis</b> ou 
            <b>📊 Consulter les statistiques d'attaques en temps réel</b>.
        </p>
    </div>
""",
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("⚙️ Configuration & À propos")
    st.info(
        "Ce système d'audit utilise le principe de k-anonymat via l'API HaveIBeenPwned. "
        "Vos mots de passe ne transitent **jamais** en clair sur le réseau."
    )
    st.markdown("---")

    st.header("📢 Actualités : Derniers Piratages")

    st.markdown(
        """
        <div class="news-card">
            <div class="news-title">🔴 France Travail (Ex-Pôle Emploi)</div>
            <div class="news-details">
                <b>Données dérobées :</b> Noms, numéros de Sécurité Sociale, identifiants et e-mails de 43 millions d'usagers.<br>
                <i>Cause :</i> Usurpation d'identifiants de conseillers.
            </div>
        </div>
        
        <div class="news-card">
            <div class="news-title">🔴 Free / Iliad</div>
            <div class="news-details">
                <b>Données dérobées :</b> Données personnelles et IBAN de plus de 19 millions d'abonnés.<br>
                <i>Cause :</i> Accès non autorisé sur un outil de gestion interne.
            </div>
        </div>

        <div class="news-card">
            <div class="news-title">🔴 Ticketmaster</div>
            <div class="news-details">
                <b>Données dérobées :</b> Noms, e-mails, téléphones et 4 derniers chiffres de cartes bancaires pour 560 millions de clients.<br>
                <i>Cause :</i> Attaque ciblant un environnement d'hébergement Snowflake.
            </div>
        </div>

        <div class="news-card">
            <div class="news-title">🔴 Viamedis & Almerys</div>
            <div class="news-details">
                <b>Données dérobées :</b> Informations de tiers payant de 33 millions de Français.<br>
                <i>Cause :</i> Phishing ciblant des professionnels de santé.
            </div>
        </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.caption("CyberShield v2.6 Pro - 2026")

tab_mdp, tab_email, tab_stats = st.tabs(
    [
        "🔑 Audit Mot de Passe",
        "📧 Analyse de Fuite E-mail",
        "📊 Télémétrie & Métriques",
    ]
)

# ==========================================
# ONGLET 1 : MOT DE PASSE
# ==========================================
with tab_mdp:
    st.subheader("Analyse de la robustesse des identifiants")

    pwd_input = st.text_input(
        "Saisissez le mot de passe à évaluer :",
        type="password",
        key="pwd_checker",
    )

    if pwd_input:
        level, score_pct, criteria = PasswordSecurityEvaluator.evaluate(
            pwd_input
        )
        pwned_count = PasswordSecurityEvaluator.check_hibp_pwned(pwd_input)

        increment_metric("tests_mdp")
        if level == "Fort":
            increment_metric("mdp_forts")
        elif level == "Moyen":
            increment_metric("mdp_moyens")
        else:
            increment_metric("mdp_faibles")

        if pwned_count and pwned_count > 0:
            increment_metric("mdp_compromis")

        log_event("PASSWORD_TEST", f"Level: {level}")

        st.markdown("#### Diagnostic")
        st.progress(score_pct / 100)

        if level == "Fort":
            st.success(f"Niveau de sécurité : **{level}** ({score_pct:.0f}%)")
        elif level == "Moyen":
            st.warning(f"Niveau de sécurité : **{level}** ({score_pct:.0f}%)")
        else:
            st.error(f"Niveau de sécurité : **{level}** ({score_pct:.0f}%)")

        col_crit, col_fuite = st.columns(2)

        with col_crit:
            st.markdown("#### Détail des critères d'évaluation")
            for crit in criteria:
                if crit.is_met:
                    st.markdown(f"✅ **{crit.description}**")
                else:
                    st.markdown(f"❌ **{crit.description}**")

        with col_fuite:
            st.markdown("#### Vérification dans les fuites publiques")
            if pwned_count is None:
                st.info("⚠️ Impossible de vérifier la présence (Erreur API).")
            elif pwned_count > 0:
                st.error(
                    f"🚨 **DANGER :** Présent **{pwned_count:,} fois** dans des fuites de données !"
                )
            else:
                st.success("✅ Aucune fuite détectée pour ce mot de passe.")

        st.markdown("---")
        st.markdown("### 🛠️ Recommandations pour améliorer votre sécurité")

        missing_criteria = [c for c in criteria if not c.is_met]

        if missing_criteria:
            st.markdown("#### Action(s) requise(s) sur la structure :")
            for crit in missing_criteria:
                st.warning(f"👉 **{crit.description}** : {crit.recommendation}")
        else:
            st.success(
                "🎉 La structure de votre mot de passe valide l'ensemble des critères de complexité."
            )

        if pwned_count and pwned_count > 0:
            st.error(
                "🚨 **Recommandation critique :** Ce mot de passe est répertorié dans des bases piratées. "
                "Ne l'utilisez sous aucun prétexte ! Si vous l'utilisez actuellement sur un compte, modifiez-le immédiatement."
            )

        with st.expander("📌 Conseils généraux pour un mot de passe robuste"):
            st.markdown(
                """
            1. **Utilisez une passphrase** : Assemblez 4 ou 5 mots aléatoires sans lien logique (ex: `Cafetière#Bleu$Trompette98!`).
            2. **Adoptez un gestionnaire de mots de passe** : Des outils comme *Bitwarden* ou *KeePass* permettent de générer et stocker des mots de passe uniques et complexes pour chaque compte.
            3. **Ne réutilisez jamais un mot de passe** : Un mot de passe unique par service garantit qu'une fuite sur un site ne compromet pas vos autres comptes.
            4. **Activez l'Authentification à Double Facteur (2FA)** : Associez toujours votre mot de passe à une application d'authentification (Google Authenticator, Authy, etc.).
            """
            )

# ==========================================
# ONGLET 2 : AUDIT E-MAIL
# ==========================================
with tab_email:
    st.subheader("Analyse d'exposition de compte e-mail")

    email_target = st.text_input(
        "Entrez l'adresse e-mail à vérifier :", placeholder="utilisateur@domaine.com"
    )
    btn_analyze = st.button("Lancer la recherche de fuites")

    if btn_analyze and email_target:
        if re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email_target):
            with st.spinner("Recherche dans les bases de données d'incidents..."):
                is_pwned, breaches = EmailBreachEvaluator.check_breaches(
                    email_target
                )

                increment_metric("tests_email")

                if is_pwned:
                    increment_metric("emails_compromis")
                    log_event("EMAIL_TEST", "Compromised")
                    st.error(
                        f"🚨 L'adresse **{email_target}** a été identifiée dans des violations de données !"
                    )

                    st.markdown("#### Services/Plateformes impactés :")
                    for breach in breaches:
                        st.warning(f"• Service compromis : **{breach}**")

                    st.markdown("---")
                    st.markdown(
                        "### 🛡️ Plan d'action recommandé en cas de fuite"
                    )

                    st.markdown(
                        """
                    <div class="recom-box">
                        <h4>1. Changez les mots de passe associés</h4>
                        <p>Modifiez immédiatement le mot de passe du service compromis ainsi que celui de votre boîte e-mail si vous utilisiez le même identifiant.</p>
                        
                        <h4>2. Activez l'Authentification à Double Facteur (2FA/MFA)</h4>
                        <p>Configurez la validation en deux étapes sur votre adresse e-mail et vos comptes majeurs (Banque, Réseaux sociaux, etc.).</p>

                        <h4>3. Restez vigilant face aux tentatives de Phishing</h4>
                        <p>Vos données (nom, e-mail, numéros) circulant sur des forums cybercriminels, méfiez-vous des e-mails ou SMS suspects demandant des actions urgentes.</p>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

                elif is_pwned is False:
                    log_event("EMAIL_TEST", "Clean")
                    st.success(
                        f"🎉 Aucune compromission connue associée à l'adresse **{email_target}**."
                    )

                    st.markdown("---")
                    st.markdown(
                        "### 💡 Conseils de prévention pour protéger votre boîte mail"
                    )
                    st.info(
                        """
                    - **Utilisez des alias e-mail** : Pour vos inscriptions secondaires, privilégiez des masques e-mail (ex: DuckDuckGo Email Protection, SimpleLogin) afin de garder votre vraie adresse confidentielle.
                    - **Vérifiez régulièrement vos accès** : Consultez régulièrement la liste des appareils connectés à votre compte de messagerie.
                    """
                    )
                else:
                    st.info(
                        "L'analyse n'a pas pu aboutir. Réessayez ultérieurement."
                    )
        else:
            st.error("Veuillez saisir un format d'adresse e-mail valide.")

# ==========================================
# ONGLET 3 : TABLEAU DE BORD STATISTIQUE
# ==========================================
with tab_stats:
    st.subheader("Télémétrie globale en temps réel")

    metrics_data = get_all_metrics()

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{metrics_data.get('visites_totales', 0)}</div>
                <div class="metric-label">Visites Totales</div>
            </div>
        """,
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{metrics_data.get('tests_mdp', 0)}</div>
                <div class="metric-label">Mots de passe analysés</div>
            </div>
        """,
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{metrics_data.get('tests_email', 0)}</div>
                <div class="metric-label">E-mails contrôlés</div>
            </div>
        """,
            unsafe_allow_html=True,
        )

    with c4:
        total_comp = metrics_data.get("mdp_compromis", 0) + metrics_data.get(
            "emails_compromis", 0
        )
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value" style="color: #F87171;">{total_comp}</div>
                <div class="metric-label">Alertes de sécurité</div>
            </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.markdown("#### Distribution de la robustesse des mots de passe")
        forts = metrics_data.get("mdp_forts", 0)
        moyens = metrics_data.get("mdp_moyens", 0)
        faibles = metrics_data.get("mdp_faibles", 0)

        total_pwd = forts + moyens + faibles
        if total_pwd > 0:
            st.write(
                f"🟢 **Forts :** {forts} ({(forts/total_pwd)*100:.1f}%)"
            )
            st.write(
                f"🟠 **Moyens :** {moyens} ({(moyens/total_pwd)*100:.1f}%)"
            )
            st.write(
                f"🔴 **Faibles :** {faibles} ({(faibles/total_pwd)*100:.1f}%)"
            )
        else:
            st.info("Aucune donnée enregistrée pour le moment.")

    with col_chart2:
        st.markdown("#### Journal d'événements récents")
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT timestamp, event_type, detail FROM telemetry ORDER BY id DESC LIMIT 5"
                )
                logs = cursor.fetchall()
                for log_time, event_type, detail in logs:
                    st.text(f"[{log_time}] {event_type} - {detail}")
        except sqlite3.Error:
            st.write("Erreur de chargement des journaux.")