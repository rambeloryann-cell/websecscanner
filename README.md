# WebSecScanner
f
Scanner de sécurité web avec authentification, historique des scans et rapports détaillés.


**WebSecScanner** est une application auto-hébergée d'analyse de sécurité web. Elle permet aux utilisateurs de soumettre une URL pour générer un rapport de vulnérabilités détaillé, vulgarisé et structuré avec un score global sur 100.

L'application intègre une isolation complète des données par compte utilisateur, un historique des scans et une sécurité renforcée (Argon2id, anti-brute force, protection CSRF).

---

## Fonctionnalités principales

* **Scan Passif (Sans danger) :** Analyse de réputation (VirusTotal, Google Web Risk), vérification DNS (SPF, DMARC) et statut SSL via crt.sh.
* **Scan Actif (Autorisation requise) :** Analyse des en-têtes HTTP de sécurité (CSP, HSTS, etc.), inspection des cookies (`Secure`, `HttpOnly`), et détection d'exposition de fichiers sensibles (`.env`, `.git`).
* **Sécurité Applicative :** Mots de passe hashés avec Argon2id, sessions stockées côté serveur dans MySQL, et limitation de requêtes via Flask-Limiter.

---

## Stack Technique

* **Backend :** Flask (Python) via le pattern *Application Factory* et Blueprints.
* **Frontend :** HTML5 / CSS3 / JS Vanilla + Bootstrap 5 (servi de manière asynchrone via `fetch`).
* **Base de données :** MySQL 8.
* **Orchestration :** Docker & Docker Compose.

---

## Prérequis (À faire avant de lancer)

Pour fonctionner correctement, le scanner a besoin de clés API externes et d'une clé secrète pour sécuriser les sessions.

1.  **Créer un compte VirusTotal :** Rendez-vous sur [VirusTotal Community](https://www.virustotal.com/) pour obtenir une clé API v3 gratuite (limite de 500 requêtes/jour).
2.  **Créer un compte Google Cloud :** Activez la **Web Risk API** sur votre console Google Cloud et générez une clé API gratuite pour l'analyse des listes noires de phishing/malware.
3.  **Générer la clé secrète Flask :** Lancez cette commande dans votre terminal pour générer une clé hautement sécurisée :
    ```bash
    python3 -c "import secrets; print(secrets.token_hex(32))"
    ```

---

## Installation et Lancement

Suivez ces étapes pour démarrer l'application dans votre environnement local :

```bash
# 1. Cloner le projet
git clone https://github.com/mrambelodk-cmyk/websecscanner
cd websecscanner

# 2. Configurer les variables d'environnement
cp .env.example .env
# Editer .env avec tes clés API

docker compose up --build
```

Ouvrir http://localhost:5000

## Comptes de démonstration

| Email | Mot de passe |
|---|---|
| admin@websec.local | Demo1234 |
| user@websec.local | Demo1234 |
