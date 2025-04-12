# Traefik-CrowdSec-Stacks

Diese Anleitung beschreibt die manuelle Installation und Konfiguration des Traefik-CrowdSec-Stacks, ohne Verwendung des automatischen Installationsskripts. Bitte folgen Sie den Schritten sorgfältig.

## Voraussetzungen

- Root-Zugriff auf den Server
- Docker und Docker Compose müssen installiert sein
- Apache2 Utils (htpasswd) und OpenSSL müssen installiert sein

## Script
![Ubuntu 20.04 - Testing](https://img.shields.io/badge/Ubuntu_20.04-07--10--2024-orange?logo=ubuntu)
![Ubuntu 22.04 - Testing](https://img.shields.io/badge/Ubuntu_22.04-07--10--2024-orange?logo=ubuntu)
![Ubuntu 24.04 - Testing](https://img.shields.io/badge/Ubuntu_24.04-07--10--2024-orange?logo=ubuntu)
![Debian 11 - Testing](https://img.shields.io/badge/Debian_11_(Bullseye)-07--10--2024-A81D33?logo=debian&logoColor=white)
![Debian 12 - Testing](https://img.shields.io/badge/Debian_12_(Bookworm)-07--10--2024-A81D33?logo=debian&logoColor=white)
### 1. Repository klonen

Als erstes müssen Sie das Repository auf Ihren Server klonen:

```bash
mkdir -p /opt/containers/
git clone https://github.com/psycho0verload/traefik-crowdsec-stack /opt/containers/traefik-crowdsec-stack
cd /opt/containers/traefik-crowdsec-stack
sudo chmod +x first_install.sh
sudo ./first_install.sh
```

## Manuelle Anleitung
![Ubuntu 20.04 - Testing](https://img.shields.io/badge/Ubuntu_20.04-07--10--2024-orange?logo=ubuntu)
![Ubuntu 22.04 - Testing](https://img.shields.io/badge/Ubuntu_22.04-07--10--2024-orange?logo=ubuntu)
![Ubuntu 24.04 - Testing](https://img.shields.io/badge/Ubuntu_24.04-07--10--2024-orange?logo=ubuntu)
![Debian 11 - Testing](https://img.shields.io/badge/Debian_11_(Bullseye)-07--10--2024-A81D33?logo=debian&logoColor=white)
![Debian 12 - Testing](https://img.shields.io/badge/Debian_12_(Bookworm)-07--10--2024-A81D33?logo=debian&logoColor=white)

Die gesamte Anleitung wird als `root`-User durchgeführt!
### 1. Repository klonen
Als erstes müssen Sie das Repository auf Ihren Server klonen:

```bash
sudo su
mkdir -p /opt/containers/
git clone https://github.com/psycho0verload/traefik-crowdsec-stack /opt/containers/traefik-crowdsec-stack
cd /opt/containers/traefik-crowdsec-stack
```

### 2. Docker und Docker Compose installieren

Falls Docker und Docker Compose noch nicht installiert sind, folgen Sie der offiziellen Anleitung:

- [Docker Installation](https://docs.docker.com/engine/install)
- [Docker Compose Installation](https://docs.docker.com/engine/install)

Verifizieren Sie die Installation mit den folgenden Befehlen:

```bash
docker --version
docker compose version
```

### 3. Apache2 Utils und OpenSSL installieren

Um einen Benutzer für die HTTP-Basic-Authentifizierung zu erstellen, benötigen Sie htpasswd, das in apache2-utils enthalten ist. Sie können es mit folgendem Befehl installieren:

```bash
apt update
apt install -y apache2-utils openssl
```

### 4. Konfigurationsdateien kopieren

Kopieren Sie die erforderlichen Konfigurationsdateien aus den .sample-Vorlagen. Stellen Sie sicher, dass Sie im Arbeitsverzeichnis des Projekts sind:

```bash
cp .env.sample .env
cp data/crowdsec/.env.sample data/crowdsec/.env
cp data/socket-proxy/.env.sample data/socket-proxy/.env
cp data/traefik/.env.sample data/traefik/.env
cp data/traefik/traefik.yml.sample data/traefik/traefik.yml
cp data/traefik/certs/acme_letsencrypt.json.sample data/traefik/certs/acme_letsencrypt.json
chmod 600 data/traefik/certs/acme_letsencrypt.json
cp data/traefik/certs/tls_letsencrypt.json.sample data/traefik/certs/tls_letsencrypt.json
chmod 600 data/traefik/certs/tls_letsencrypt.json
cp data/traefik/dynamic_conf/http.middlewares.default.yml.sample data/traefik/dynamic_conf/http.middlewares.default.yml
cp data/traefik/dynamic_conf/http.middlewares.default-security-headers.yml.sample data/traefik/dynamic_conf/http.middlewares.default-security-headers.yml
cp data/traefik/dynamic_conf/http.middlewares.gzip.yml.sample data/traefik/dynamic_conf/http.middlewares.gzip.yml
cp data/traefik/dynamic_conf/http.middlewares.traefik-bouncer.yml.sample data/traefik/dynamic_conf/http.middlewares.traefik-bouncer.yml
cp data/traefik/dynamic_conf/http.middlewares.traefik-dashboard-auth.yml.sample data/traefik/dynamic_conf/http.middlewares.traefik-dashboard-auth.yml
cp data/traefik/dynamic_conf/tls.yml.sample data/traefik/dynamic_conf/tls.yml
cp data/traefik-crowdsec-bouncer/.env.sample data/traefik-crowdsec-bouncer/.env
```

### 5. SSL-Zertifikate und Domain konfigurieren

Fügen Sie Ihre SSL-Zertifikats-E-Mail-Adresse und die gewünschte Domain für das Traefik-Dashboard in die entsprechenden Konfigurationsdateien ein:

1.	Bearbeiten Sie die `data/traefik/traefik.yml` und ersetzen Sie die E-Mail-Adressen (die Adressen **müssen** identisch sein):
    ```yaml
    certificatesResolvers:
      http_resolver:
        acme:
          email: "deine@email.de"
          storage: "/etc/traefik/acme_letsencrypt.json"
          httpChallenge:
            entryPoint: web
      tls_resolver:
        acme:
          email: "deine@email.de"
          storage: "/etc/traefik/tls_letsencrypt.json"
          tlsChallenge: {}
    ```

2.	In der Datei `.env` setzen Sie die gewünschte Domain für das Traefik-Dashboard:

    ```bash
    SERVICES_TRAEFIK_LABELS_TRAEFIK_HOST=HOST(`traefik.yourdomain.com`)
    ```

### 6. CrowdSec konfigurieren
1. CrowdSec Konfigurationsdatein erstellen
    ```bash
    cd /opt/containers/traefik-crowdsec-stack/
    docker compose up -d crowdsec && docker compose down
    ```

2.	Acquis.yaml anpassen: Bearbeiten Sie die `/opt/containers/traefik-crowdsec-stack/data/crowdsec/config/acquis.yaml`, löschen Sie alle Zeilen und fügen Sie die folgenden Zeilen hinzu:
    ```yaml
    filenames:
     - /var/log/auth.log
     - /var/log/syslog
    labels:
      type: syslog
    ---
    filenames:
     - /var/log/traefik/access.log
    labels:
      type: traefik
    ---
    ```

3. Token generieren für den CrowdSec Bouncer für Trafik
    ```bash
    BOUNCER_KEY_TRAEFIK=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#$%^&*()-_=+[]{}<>?|')
    BOUNCER_KEY_FIREWALL=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#$%^&*()-_=+[]{}<>?|')
    echo "BOUNCER_KEY_TRAEFIK=\"$BOUNCER_KEY_TRAEFIK\"" >> /opt/containers/traefik-crowdsec-stack/.env
    echo "BOUNCER_KEY_FIREWALL=\"$BOUNCER_KEY_FIREWALL\"" >> /opt/containers/traefik-crowdsec-stack/.env
    echo "Generated BOUNCER_KEY_FIREWALL: $BOUNCER_KEY_FIREWALL"
    ```
4. Speichern Sie sich den Token für BOUNCER_KEY_FIREWALL! Diesen benötigen Sie später nochmal!

### 7. Benutzer und Passwort für das Dashboard erstellen

Erstellen Sie einen Benutzer und ein Passwort für die HTTP-Basic-Authentifizierung im Traefik-Dashboard:

```bash
htpasswd -c /opt/containers/traefik-crowdsec-stack/data/traefik/.htpasswd <deinBenutzername>
```

### 8. Firewall Bouncer
1. Installieren Sie die Repositories von CrowdSec
    ```bash
    curl -s https://install.crowdsec.net | sudo sh
    ```
2. Installieren Sie den Service für Ihre Firewall

    **IPTables und UFW**
    ```bash
    sudo apt install crowdsec-firewall-bouncer-iptables
    ```
    **NFTables**
    ```bash
    sudo apt install crowdsec-firewall-bouncer-nftables
    ```

3.	Firewall-Konfiguration anpassen: Bearbeiten Sie die Datei `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`:
    ```
    api_url: http://172.31.127.254:8080/
    api_key: <BOUNCER_KEY_FIREWALL>
    ```
Der `BOUNCER_KEY_FIREWALL` sollte der Wert sein, den Sie generiert haben (in Schritt 6.3.).

4. Firewall neustarten
    ```
    systemctl enable crowdsec-firewall-bouncer
    systemctl restart crowdsec-firewall-bouncer
    ```


### 9. Firewall-Ports überprüfen

Stellen Sie sicher, dass die Firewall die Ports 80 (HTTP) und 443 (HTTPS) freigibt.

### 10. Domain überprüfen

Vergewissern Sie sich, dass die von Ihnen gewählte Domain korrekt auf die IP-Adresse des Servers verweist.

### 11. Stack starten

Sobald alle Konfigurationen abgeschlossen sind, können Sie den Stack starten:

```bash
docker compose up -d
```

### 12. Zugriff auf das Traefik-Dashboard

Das Traefik-Dashboard sollte nun über die von Ihnen konfigurierte Domain erreichbar sein. Sie werden zur Eingabe des HTTP-Basic-Auth-Benutzernamens und Passworts aufgefordert.

https://traefik.yourdomain.com