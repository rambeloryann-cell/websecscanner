import requests
import ssl
import socket
import re
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

SECURITY_HEADERS = {
    'Content-Security-Policy': ('critical', 'Sans ce header, un attaquant peut injecter du JavaScript malveillant (XSS).', 'Ajouter : Content-Security-Policy: default-src \'self\''),
    'Strict-Transport-Security': ('high', 'Sans HSTS, un attaquant peut forcer le navigateur à utiliser HTTP non chiffré.', 'Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains'),
    'X-Frame-Options': ('high', 'La page peut être intégrée dans une iframe pour tromper l\'utilisateur (clickjacking).', 'Ajouter : X-Frame-Options: DENY'),
    'X-Content-Type-Options': ('medium', 'Le navigateur peut interpréter des fichiers avec un mauvais type MIME.', 'Ajouter : X-Content-Type-Options: nosniff'),
    'Referrer-Policy': ('medium', 'L\'URL complète peut être transmise à des sites tiers.', 'Ajouter : Referrer-Policy: strict-origin-when-cross-origin'),
    'Permissions-Policy': ('low', 'Des scripts tiers peuvent accéder à la caméra, au micro ou à la géolocalisation.', 'Ajouter : Permissions-Policy: camera=(), microphone=(), geolocation=()'),
}


def run_active_scan(url):
    results = []
    results += _headers(url)
    results += _tls(url)
    results += _cookies(url)
    results += _exposure(url)
    return results


def _headers(url):
    results = []
    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        for header, (sev, risk, fix) in SECURITY_HEADERS.items():
            if header.lower() in headers_lower:
                results.append(_pass('headers', header, f'Header {header} présent.', 'Aucune action requise.'))
            else:
                results.append(_fail('headers', header, sev, f'Header {header} absent. {risk}', fix))
    except Exception as e:
        results.append(_na('headers', 'Headers HTTP', f'Impossible de récupérer les headers : {str(e)}', 'Vérifier que l\'URL est accessible.'))
    return results


def _tls(url):
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        return [_fail('ssl', 'TLS — Protocole', 'critical', 'Le site n\'utilise pas HTTPS. Les données transitent en clair.', 'Configurer HTTPS avec un certificat valide.')]

    hostname = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
        if version in ('TLSv1', 'TLSv1.1'):
            return [_fail('ssl', 'TLS — Version', 'high', f'Version obsolète : {version}. Vulnérable à des attaques connues.', 'Désactiver TLS 1.0 et 1.1. Utiliser TLS 1.2 minimum.')]
        return [_pass('ssl', 'TLS — Version', f'Version à jour : {version}.', 'Aucune action requise.')]
    except Exception as e:
        return [_na('ssl', 'TLS — Version', f'Impossible de vérifier TLS : {str(e)}', 'Vérifier l\'accès au port 443.')]


def _cookies(url):
    results = []
    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        if not resp.cookies:
            return [_pass('cookies', 'Cookies', 'Aucun cookie détecté.', 'Aucune action requise.')]
        for cookie in resp.cookies:
            issues = []
            sev = 'low'
            if not cookie.secure:
                issues.append('flag Secure absent')
                sev = 'high'
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append('flag HttpOnly absent')
                if sev != 'high':
                    sev = 'medium'
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append('SameSite absent')
                if sev == 'low':
                    sev = 'medium'
            if issues:
                results.append(_fail('cookies', f'Cookie : {cookie.name}', sev,
                    f'Cookie "{cookie.name}" mal configuré : {", ".join(issues)}.',
                    f'Set-Cookie: {cookie.name}=valeur; Secure; HttpOnly; SameSite=Strict'))
            else:
                results.append(_pass('cookies', f'Cookie : {cookie.name}', f'Cookie "{cookie.name}" correctement configuré.', 'Aucune action requise.'))
    except Exception as e:
        results.append(_na('cookies', 'Cookies', f'Impossible d\'analyser les cookies : {str(e)}', 'Vérifier que l\'URL est accessible.'))
    return results


def _exposure(url):
    results = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Server header
    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        server = resp.headers.get('Server', '') or resp.headers.get('server', '')
        if server:
            if re.search(r'[\d.]{3,}', server):
                results.append(_fail('exposure', 'Server header', 'medium', f'Version exposée dans le header Server : "{server}".', 'Masquer la version : ServerTokens Prod (Apache) ou server_tokens off (Nginx).'))
            else:
                results.append(_pass('exposure', 'Server header', f'Header Server sans version : "{server}".', 'Aucune action requise.'))
        else:
            results.append(_pass('exposure', 'Server header', 'Header Server absent. Bonne pratique.', 'Aucune action requise.'))
    except Exception:
        pass

    # Fichiers sensibles
    paths = [
        ('/.env', 'critical', 'Fichier .env exposé. Contient potentiellement des clés API et mots de passe.'),
        ('/.git/config', 'critical', 'Répertoire .git exposé. Le code source est accessible.'),
        ('/phpinfo.php', 'high', 'phpinfo() accessible. Expose la configuration PHP et les chemins système.'),
        ('/admin', 'medium', 'Panneau d\'administration accessible.'),
        ('/debug', 'high', 'Endpoint de debug accessible.'),
        ('/robots.txt', 'low', 'robots.txt accessible. Peut révéler des chemins internes.'),
    ]
    for path, sev, desc in paths:
        try:
            r = requests.get(base + path, timeout=5, verify=False, allow_redirects=False)
            if r.status_code in (200, 301, 302):
                results.append(_fail('exposure', f'Fichier sensible : {path}', sev, desc, f'Bloquer l\'accès à {path} dans la config du serveur web.'))
        except Exception:
            pass

    return results


def _pass(cat, name, desc, rec):
    return {'category': cat, 'check_name': name, 'check_mode': 'active', 'status': 'pass', 'severity': 'low', 'description': desc, 'recommendation': rec}

def _fail(cat, name, sev, desc, rec):
    return {'category': cat, 'check_name': name, 'check_mode': 'active', 'status': 'fail', 'severity': sev, 'description': desc, 'recommendation': rec}

def _na(cat, name, desc, rec):
    return {'category': cat, 'check_name': name, 'check_mode': 'active', 'status': 'na', 'severity': 'low', 'description': desc, 'recommendation': rec}
