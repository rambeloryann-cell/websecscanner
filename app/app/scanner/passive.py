import requests
import dns.resolver
import os
import base64
from urllib.parse import urlparse
from datetime import datetime


def run_passive_scan(url):
    parsed = urlparse(url)
    domain = parsed.hostname
    results = []
    results += _virustotal(url)
    results += _webrisk(url)
    results += _dns(domain)
    results += _crtsh(domain)
    return results


def _virustotal(url):
    api_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not api_key or api_key == 'ta_cle_ici':
        return [_na('reputation', 'VirusTotal', 'Clé API VirusTotal non configurée dans .env', 'Ajouter VIRUSTOTAL_API_KEY dans .env')]

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        r = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': api_key},
            timeout=15
        )
        if r.status_code == 200:
            stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            if malicious == 0:
                return [_pass('reputation', 'VirusTotal', f'Aucun moteur ne signale cette URL ({malicious}/{total}).', 'Aucune action requise.')]
            else:
                return [_fail('reputation', 'VirusTotal', 'critical', f'{malicious}/{total} moteurs signalent cette URL comme malveillante.', 'Investiguer immédiatement.')]
        elif r.status_code == 404:
            # URL jamais analysée, soumettre pour analyse
            try:
                sub = requests.post(
                    'https://www.virustotal.com/api/v3/urls',
                    headers={'x-apikey': api_key},
                    data={'url': url},
                    timeout=10
                )
                return [_pass('reputation', 'VirusTotal', 'URL soumise pour analyse. Résultats disponibles dans quelques minutes.', 'Aucune action requise.')]
            except Exception:
                return [_na('reputation', 'VirusTotal', 'URL inconnue de VirusTotal.', 'Soumettre manuellement sur virustotal.com')]
        else:
            return [_na('reputation', 'VirusTotal', f'Erreur API VirusTotal (HTTP {r.status_code}).', 'Vérifier la clé API.')]
    except Exception as e:
        return [_na('reputation', 'VirusTotal', f'Erreur connexion VirusTotal : {str(e)}', 'Vérifier la connexion internet.')]


def _webrisk(url):
    api_key = os.environ.get('GOOGLE_WEBRISK_API_KEY', '')
    if not api_key or api_key == 'ta_cle_ici':
        return [_na('reputation', 'Google Web Risk', 'Clé API Google Web Risk non configurée dans .env', 'Ajouter GOOGLE_WEBRISK_API_KEY dans .env')]

    try:
        threat_types = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE']
        params = {
            'key': api_key,
            'uri': url,
        }
        for t in threat_types:
            params.setdefault('threatTypes', []).append(t)

        # Utiliser l'API Web Risk v1
        r = requests.get(
            'https://webrisk.googleapis.com/v1/uris:search',
            params={
                'key': api_key,
                'uri': url,
                'threatTypes': threat_types
            },
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            if data.get('threat'):
                threat_type = data['threat'].get('threatTypes', ['inconnu'])[0]
                return [_fail('reputation', 'Google Web Risk', 'critical', f'URL signalée par Google : {threat_type}.', 'Ne pas visiter cette URL.')]
            else:
                return [_pass('reputation', 'Google Web Risk', 'URL absente des listes noires Google.', 'Aucune action requise.')]
        else:
            return [_na('reputation', 'Google Web Risk', f'Erreur API Google (HTTP {r.status_code}).', 'Vérifier la clé API Web Risk.')]
    except Exception as e:
        return [_na('reputation', 'Google Web Risk', f'Erreur connexion Google Web Risk : {str(e)}', 'Vérifier la connexion internet.')]


def _dns(domain):
    results = []

    # SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        spf = any('v=spf1' in str(r) for r in answers)
        if spf:
            results.append(_pass('dns', 'SPF', 'Enregistrement SPF présent.', 'Aucune action requise.'))
        else:
            results.append(_fail('dns', 'SPF', 'medium', 'Aucun enregistrement SPF. N\'importe qui peut envoyer des emails en usurpant ce domaine.', 'Ajouter un TXT : v=spf1 mx ~all'))
    except Exception:
        results.append(_fail('dns', 'SPF', 'medium', 'Impossible de résoudre les enregistrements TXT DNS.', 'Vérifier que le domaine est valide.'))

    # DMARC
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=5)
        dmarc = any('v=DMARC1' in str(r) for r in answers)
        if dmarc:
            results.append(_pass('dns', 'DMARC', 'Enregistrement DMARC présent.', 'Aucune action requise.'))
        else:
            results.append(_fail('dns', 'DMARC', 'medium', 'Aucun enregistrement DMARC. Les emails frauduleux ne sont pas bloqués.', 'Ajouter un TXT sur _dmarc : v=DMARC1; p=none; rua=mailto:dmarc@domaine.com'))
    except Exception:
        results.append(_fail('dns', 'DMARC', 'medium', 'Aucun enregistrement DMARC trouvé.', 'Ajouter un TXT sur _dmarc : v=DMARC1; p=none; rua=mailto:dmarc@domaine.com'))

    return results


def _crtsh(domain):
    try:
        r = requests.get(f'https://crt.sh/?q={domain}&output=json', timeout=10)
        if r.status_code == 200:
            certs = r.json()
            if certs:
                latest = max(certs, key=lambda c: c.get('not_after', ''))
                not_after = latest.get('not_after', '')
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
                    except ValueError:
                        expiry = datetime.strptime(not_after[:10], '%Y-%m-%d')
                    days = (expiry - datetime.utcnow()).days
                    if days < 0:
                        return [_fail('ssl', 'Certificat SSL (crt.sh)', 'critical', f'Certificat SSL expiré depuis {abs(days)} jours.', 'Renouveler le certificat immédiatement.')]
                    elif days < 30:
                        return [_fail('ssl', 'Certificat SSL (crt.sh)', 'high', f'Certificat SSL expire dans {days} jours.', 'Renouveler rapidement.')]
                    else:
                        return [_pass('ssl', 'Certificat SSL (crt.sh)', f'Certificat valide, expire dans {days} jours.', 'Aucune action requise.')]
    except Exception as e:
        pass
    return [_na('ssl', 'Certificat SSL (crt.sh)', 'Impossible de vérifier via crt.sh.', 'Vérifier manuellement.')]


# Helpers
def _pass(cat, name, desc, rec):
    return {'category': cat, 'check_name': name, 'check_mode': 'passive', 'status': 'pass', 'severity': 'low', 'description': desc, 'recommendation': rec}

def _fail(cat, name, sev, desc, rec):
    return {'category': cat, 'check_name': name, 'check_mode': 'passive', 'status': 'fail', 'severity': sev, 'description': desc, 'recommendation': rec}

def _na(cat, name, desc, rec):
    return {'category': cat, 'check_name': name, 'check_mode': 'passive', 'status': 'na', 'severity': 'low', 'description': desc, 'recommendation': rec}
