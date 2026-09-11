import hashlib
import re
import requests
import streamlit as st

# 1. Configuration de la page
st.set_page_config(
    page_title="CyberShield - Audit de Sécurité",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# 2. Injection de styles CSS personnalisés pour un design Cyber/SaaS moderne
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }
    
    /* Arrière-plan global sombre */
    .stApp {
        background-color: #0B0F19;
        color: #E2E8F0;
    }
    
    /* En-tête principal */
    .header-container {
        text-align: center;
        padding: 20px 0 10px 0;
    }
    
    .main-title {
        background: linear-gradient(135deg, #60A5FA 0%, #A855F7 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.4rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        margin-bottom: 8px;
    }
    
    .sub-title {
        color: #94A3B8;
        font-size: 1rem;
        margin-bottom: 25px;
    }
    
    /* Cartes de contenu */
    .cyber-card {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 24px;
        margin-top: 15px;
        margin-bottom: 20px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
    }
    
    /* Badges de niveau de force */
    .badge-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 12px;
    }
    
    .badge-strength {
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.95rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .badge-fort {
        background-color: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid #10B981;
    }
    
    .badge-moyen {
        background-color: rgba(245, 158, 11, 0.15);
        color: #FBBF24;
        border: 1px solid #F59E0B;
    }
    
    .badge-faible {
        background-color: rgba(239, 68, 68, 0.15);
        color: #F87171;
        border: 1px solid #EF4444;
    }
    
    /* Barre de progression de robustesse */
    .progress-bg {
        background-color: #0F172A;
        border-radius: 10px;
        height: 10px;
        width: 100%;
        overflow: hidden;
        margin-bottom: 20px;
        border: 1px solid #334155;
    }
    
    .bar-fort {
        background: linear-gradient(90deg, #10B981, #34D399);
        height: 100%;
        width: 100%;
    }
    
    .bar-moyen {
        background: linear-gradient(90deg, #F59E0B, #FBBF24);
        height: 100%;
        width: 60%;
    }
    
    .bar-faible {
        background: linear-gradient(90deg, #EF4444, #F87171);
        height: 100%;
        width: 25%;
    }
    
    /* Items de critères de sécurité */
    .criterion-item {
        padding: 10px 14px;
        border-radius: 10px;
        margin-bottom: 8px;
        font-size: 0.92rem;
        font-weight: 500;
        display: flex;
        align-items: center;
    }
    
    .criterion-valid {
        background-color: rgba(16, 185, 129, 0.08);
        color: #6EE7B7;
        border-left: 4px solid #10B981;
    }
    
    .criterion-invalid {
        background-color: rgba(239, 68, 68, 0.08);
        color: #FCA5A5;
        border-left: 4px solid #EF4444;
    }
    
    /* Cartes de fuites de données */
    .breach-pill {
        background-color: #0F172A;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 12px 16px;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    
    .breach-name {
        color: #F1F5F9;
        font-weight: 600;
        font-size: 1rem;
    }
    
    /* Style personnalisé pour les onglets */
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
        background-color: #0F172A;
        padding: 6px;
        border-radius: 14px;
        border: 1px solid #1E293B;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 48px;
        border-radius: 10px;
        color: #94A3B8;
        font-weight: 600;
        border: none !important;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #1E293B !important;
        color: #60A5FA !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    
    /* Champs de saisie */
    .stTextInput>div>div>input {
        background-color: #0F172A !important;
        color: #F8FAFC !important;
        border: 1px solid #334155 !important;
        border-radius: 12px !important;
        padding: 12px 16px !important;
    }
    
    .stTextInput>div>div>input:focus {
        border-color: #3B82F6 !important;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3) !important;
    }
    
    /* Boutons principaux */
    .stButton>button {
        width: 100%;
        background: linear-gradient(135deg, #2563EB 0%, #1D4ED8 100%);
        color: white;
        font-weight: 600;
        border-radius: 12px;
        padding: 12px 24px;
        border: none;
        transition: all 0.3s ease;
        box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35);
    }
    
    .stButton>button:hover {
        background: linear-gradient(135deg, #1D4ED8 0%, #1E40AF 100%);
        box-shadow: 0 6px 20px rgba(37, 99, 235, 0.5);
    }
</style>
""",
    unsafe_allow_dict=True,
)

# 3. Header principal
st.markdown(
    """
<div class="header-container">
    <div class="main-title">🛡️ CyberShield Verification</div>
    <div class="sub-title">Audit instantané de la robustesse des mots de passe et vérification d'exposition de vos e-mails</div>
</div>
""",
    unsafe_allow_dict=True,
)

# Onglets principaux
tab1, tab2 = st.tabs(
    ["🔑 Robustesse & Fuites de Mot de Passe", "📧 Audit d'E-mail"]
)

# ==========================================
# FONCTIONS LOGIQUES
# ==========================================


def evaluer_mot_de_passe(mypass):
    """Évalue les criteres et calcule la force du mot de passe."""
    criteria = [
        (
            len(mypass) >= 12,
            "Longueur minimale de 12 caractères",
            "Augmentez la longueur à au moins 12 caractères",
        ),
        (
            bool(re.search(r"[A-Z]", mypass)),
            "Présence de lettres majuscules (A-Z)",
            "Ajoutez au moins une majuscule",
        ),
        (
            bool(re.search(r"[a-z]", mypass)),
            "Présence de lettres minuscules (a-z)",
            "Ajoutez au moins une minuscule",
        ),
        (
            bool(re.search(r"[0-9]", mypass)),
            "Présence de chiffres (0-9)",
            "Ajoutez au moins un chiffre",
        ),
        (
            bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', mypass)),
            "Présence de symboles spéciaux (@, #, $, !...)",
            "Ajoutez un caractère spécial",
        ),
    ]

    valides = [c for c in criteria if c[0]]
    score = len(valides)

    if score >= 5:
        force, class_style, bar_style = "Fort", "badge-fort", "bar-fort"
    elif score >= 3:
        force, class_style, bar_style = "Moyen", "badge-moyen", "bar-moyen"
    else:
        force, class_style, bar_style = "Faible", "badge-faible", "bar-faible"

    return force, class_style, bar_style, criteria


def verifier_fuite_mot_de_passe(mypass):
    """Interroge l'API HIBP via k-Anonymity (SHA-1 prefix)."""
    sha1_hash = hashlib.sha1(mypass.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            hashes = (line.split(":") for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
            return 0
        return None
    except Exception:
        return None


def verifier_fuite_email(email):
    """Vérifie l'exposition d'un e-mail via l'API XposedOrNot."""
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "breaches" in data and data["breaches"]:
                return True, data["breaches"][0]
            return False, []
        return False, []
    except Exception:
        return None, []


# ==========================================
# ONGLET 1 : MOT DE PASSE
# ==========================================
with tab1:
    password = st.text_input(
        "Entrez un mot de passe à tester :",
        type="password",
        placeholder="Tapez votre mot de passe...",
    )

    if password:
        force, badge_class, bar_class, criteria = evaluer_mot_de_passe(
            password
        )

        # Affichage du score et de la jauge
        st.markdown(
            f"""
        <div class="cyber-card">
            <div class="badge-container">
                <span style="font-weight: 600; color: #94A3B8;">Niveau de sécurité :</span>
                <span class="badge-strength {badge_class}">{force}</span>
            </div>
            <div class="progress-bg">
                <div class="{bar_class}"></div>
            </div>
        </div>
        """,
            unsafe_allow_dict=True,
        )

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### 📋 Critères d'évaluation")
            for valid, text, rec in criteria:
                icon = "✔" if valid else "✖"
                css_class = "criterion-valid" if valid else "criterion-invalid"
                st.markdown(
                    f'<div class="criterion-item {css_class}">{icon} {text}</div>',
                    unsafe_allow_dict=True,
                )

        with col2:
            st.markdown("#### 💡 Recommandations")
            recs = [rec for valid, text, rec in criteria if not valid]
            if recs:
                for r in recs:
                    st.markdown(f"• {r}")
            else:
                st.success("Excellente combinaison ! Votre mot de passe suit les meilleures pratiques de sécurité.")

        st.markdown("---")

        # Vérification des fuites de mots de passe
        st.markdown("#### 🔍 Recherche dans les bases de fuites publiques")
        with st.spinner("Analyse anonymisée via l'API HIBP..."):
            nb_fuites = verifier_fuite_mot_de_passe(password)

        if nb_fuites is not None:
            if nb_fuites > 0:
                st.error(
                    f"⚠️ **Compromission détectée !** Ce mot de passe a été trouvé **{nb_fuites:,} fois** dans des bases de données piratées. Il ne doit **absolument plus être utilisé**."
                )
                st.caption(
                    "ℹ️ *Votre mot de passe est préservé : seuls les 5 premiers caractères de son empreinte SHA-1 sont transmis pour effectuer cette vérification anonyme.*"
                )
            else:
                st.success(
                    "✅ Ce mot de passe n'apparaît dans aucune fuite de données répertoriée."
                )

# ==========================================
# ONGLET 2 : AUDIT E-MAIL
# ==========================================
with tab2:
    st.markdown("### Vérifier la confidentialité d'une adresse e-mail")
    email_input = st.text_input(
        "Adresse e-mail à vérifier :", placeholder="ex: nom@domaine.com"
    )

    if st.button("Lancer l'analyse de fuites"):
        if email_input and "@" in email_input and "." in email_input:
            with st.spinner("Analyse des bases de violations de données..."):
                is_pwned, plateformes = verifier_fuite_email(email_input)

            if is_pwned is True and plateformes:
                st.error(
                    f"🚨 L'adresse **{email_input}** apparaît dans plusieurs fuites de données publiques !"
                )

                st.markdown("#### Plateformes concernées :")
                for site in plateformes:
                    st.markdown(
                        f"""
                    <div class="breach-pill">
                        <span class="breach-name">🌐 {site}</span>
                        <span style="color: #F87171; font-size: 0.85rem; font-weight: 600;">Données compromises</span>
                    </div>
                    """,
                        unsafe_allow_dict=True,
                    )

                st.info(
                    "🔒 **Actions recommandées :** Changez immédiatement les mots de passe associés à ces services et activez la vérification en deux étapes (2FA)."
                )

            elif is_pwned is False:
                st.success(
                    f"🎉 Bonne nouvelle ! Aucune fuite connue n'a été associée à l'adresse **{email_input}**."
                )
            else:
                st.warning(
                    "Impossible de contacter le service de vérification. Veuillez réessayer plus tard."
                )
        else:
            st.warning(
                "Veuillez saisir une adresse e-mail valide avant de lancer la recherche."
            )