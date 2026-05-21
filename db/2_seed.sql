INSERT INTO users (username, email, password_hash) VALUES
('admin', 'admin@websec.local', '$argon2id$v=19$m=65536,t=3,p=4$sXa1miSMgGXFKJM46CXlFA$3d60YJij1GXk5zy5bSNlxXobS7iK9LmhgHoTqeHxFAQ'),
('user',  'user@websec.local',  '$argon2id$v=19$m=65536,t=3,p=4$5DnwMFiu4jcTI+uZ14h1cA$EIsqhVKDoB+0FPU1v0GP4f1uNXTVXcRqF6ymgUvLwxE');

INSERT INTO scans (user_id, url, mode, score, status) VALUES
(1, 'https://scanme.nmap.org', 'passive', 72, 'done');

INSERT INTO scan_results (scan_id, category, check_name, check_mode, status, severity, description, recommendation) VALUES
(1, 'reputation', 'VirusTotal', 'passive', 'pass', 'low', 'Aucun moteur antivirus ne signale cette URL (0/85).', 'Aucune action requise.'),
(1, 'reputation', 'Google Web Risk', 'passive', 'pass', 'low', 'URL absente des listes noires Google.', 'Aucune action requise.'),
(1, 'dns', 'SPF', 'passive', 'fail', 'medium', 'Aucun enregistrement SPF trouvé pour ce domaine.', 'Ajouter un enregistrement TXT : v=spf1 mx ~all'),
(1, 'dns', 'DMARC', 'passive', 'fail', 'medium', 'Aucun enregistrement DMARC configuré.', 'Ajouter : v=DMARC1; p=none; rua=mailto:dmarc@domaine.com'),
(1, 'ssl', 'Certificat SSL (crt.sh)', 'passive', 'pass', 'low', 'Certificat valide, expire dans 187 jours.', 'Aucune action requise.');
