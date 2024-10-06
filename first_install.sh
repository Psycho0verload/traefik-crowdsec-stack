#!/bin/bash

# Funktion zum Anzeigen von Schritten mit Fortschrittspunkten
print_step() {
    echo -e "\n\e[1;34m[Schritt $1/$TOTAL_STEPS]:\e[0m $2"
}

# Funktion zum Überprüfen, ob ein Befehl erfolgreich war
check_success() {
    if [ $? -ne 0 ]; then
        echo -e "\e[1;31mFehler beim Ausführen von: $1\e[0m"
        exit 1
    fi
}

# Gesamtzahl der Schritte
TOTAL_STEPS=12
CURRENT_STEP=0

# Erster Schritt: Arbeitsverzeichnis setzen
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Setze das Arbeitsverzeichnis auf das Verzeichnis, in dem das Skript liegt"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd "$SCRIPT_DIR" || exit

# Zweiter Schritt: Überprüfen, ob das Skript als Root ausgeführt wird
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Überprüfen, ob das Skript als Root ausgeführt wird"
if [ "$EUID" -ne 0 ]; then
    echo -e "\e[1;31mBitte führe das Skript mit Root-Rechten aus.\e[0m"
    exit 1
fi

# Dritter Schritt: Überprüfen, ob Docker installiert ist
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Überprüfen, ob Docker installiert ist"
if ! command -v docker &> /dev/null; then
    echo -e "\e[1;31mDocker ist nicht installiert. Bitte folge der Anleitung unter: https://docs.docker.com/engine/install/\e[0m"
    exit 1
fi

# Vierter Schritt: Überprüfen, ob Docker Compose installiert ist
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Überprüfen, ob Docker Compose installiert ist"
if ! command -v docker compose &> /dev/null; then
    echo -e "\e[1;31mDocker Compose ist nicht installiert. Bitte folge der Anleitung unter: https://docs.docker.com/engine/install/\e[0m"
    exit 1
fi

# Fünfter Schritt: apache2-utils (htpasswd) installieren, falls nicht vorhanden
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Installiere apache2-utils (htpasswd), falls nicht vorhanden"
command -v htpasswd >/dev/null 2>&1 || { sudo apt update && sudo apt install -y apache2-utils; }
check_success "apache2-utils Installation"

# Sechster Schritt: Überprüfen, ob Container bereits laufen
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Überprüfen, ob Container bereits laufen"
containers=("crowdsec" "socket-proxy" "traefik" "traefik_crowdsec_bouncer")
for container in "${containers[@]}"; do
  if [ "$(docker ps -q -f name=$container)" ]; then
    echo -e "\e[1;31mDer Docker-Container '$container' läuft bereits. Das Skript wird abgebrochen.\e[0m"
    exit 1
  fi
done

# Siebter Schritt: Netzwerke überprüfen
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Überprüfen, ob Netzwerke bereits existieren"
networks=("proxy" "socket_proxy" "crowdsec")
for network in "${networks[@]}"; do
  if [ "$(docker network ls -q -f name=^${network}$)" ]; then
    echo -e "\e[1;31mDas Docker-Netzwerk '$network' existiert bereits. Das Skript wird abgebrochen.\e[0m"
    exit 1
  fi
done

# Achter Schritt: Dateien kopieren, wenn die jeweilige .sample Datei vorhanden ist
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Kopiere Dateien, wenn die jeweilige .sample Datei vorhanden ist"
files_to_copy=(
  ".env.sample .env"
  "data/crowdsec/.env.sample data/crowdsec/.env"
  "data/socket-proxy/.env.sample data/socket-proxy/.env"
  "data/traefik/.env.sample data/traefik/.env"
  "data/traefik/traefik.yml.sample data/traefik/traefik.yml"
  "data/traefik/certs/acme_letsencrypt.json.sample data/traefik/certs/acme_letsencrypt.json"
  "data/traefik/certs/tls_letsencrypt.json.sample data/traefik/certs/tls_letsencrypt.json"
  "data/traefik/dynamic_conf/http.middlewares.default.yml.sample data/traefik/dynamic_conf/http.middlewares.default.yml"
  "data/traefik/dynamic_conf/http.middlewares.traefik-bouncer.yml.sample data/traefik/dynamic_conf/http.middlewares.traefik-bouncer.yml"
  "data/traefik/dynamic_conf/http.middlewares.traefik-dashboard-auth.yml.sample data/traefik/dynamic_conf/http.middlewares.traefik-dashboard-auth.yml"
  "data/traefik/dynamic_conf/tls.yml.sample data/traefik/dynamic_conf/tls.yml"
  "data/traefik-crowdsec-bouncer/.env.sample data/traefik-crowdsec-bouncer/.env"
)
for file_pair in "${files_to_copy[@]}"; do
  src=$(echo $file_pair | awk '{print $1}')
  dst=$(echo $file_pair | awk '{print $2}')
  # Absoluter Pfad der Dateien
  src_path="${SCRIPT_DIR}/${src}"
  dst_path="${SCRIPT_DIR}/${dst}"
  if [ -f "$src_path" ]; then
    cp "$src_path" "$dst_path"
    echo -e "\e[1;32mKopiere ${src_path} nach ${dst_path}\e[0m"
  else
    echo -e "\e[1;31mDie Datei ${src_path} existiert nicht. Das Skript wird abgebrochen.\e[0m"
    exit 1
  fi
done

# Neunter Schritt: Benutzer nach Domain und E-Mail-Adresse fragen
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Benutzer nach der Wunsch-Domain und E-Mail-Adresse fragen"
# Funktion zur Überprüfung der E-Mail-Adresse
validate_email() {
  local email_regex="^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
  if [[ $1 =~ $email_regex ]]; then
    return 0  # gültige E-Mail
  else
    return 1  # ungültige E-Mail
  fi
}

while true; do
  read -p "Bitte gib deine E-Mail-Adresse für die SSL-Zertifikate ein: " ssl_email
  if validate_email "$ssl_email"; then
    echo -e "\e[1;32mGültige E-Mail-Adresse eingegeben: $ssl_email\e[0m"
    break
  else
    echo -e "\e[1;31mUngültige E-Mail-Adresse. Bitte versuche es erneut.\e[0m"
  fi
done

read -p "Bitte gib die Wunsch-Domain für dein Traefik-Dashboard ein: " dashboard_domain

# Zehnter Schritt: Konfiguration von CrowdSec und der Firewall anpassen
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Konfiguration von CrowdSec und der Firewall anpassen"
# Benutzer für Dashboard setzen
htpasswd_file="/opt/containers/traefik-crowdsec-stack/data/traefik/.htpasswd"
sudo htpasswd -c "$htpasswd_file" "$dashboard_user"
check_success "Dashboard Benutzer und Passwort setzen"

# Letzter Schritt: Finaler Check und Erinnerung an den Benutzer
CURRENT_STEP=$((CURRENT_STEP + 1))
print_step $CURRENT_STEP "Finaler Check: Firewall und Domain überprüfen"
echo -e "\e[1;33mBevor du den Stack startest, stelle bitte sicher, dass:\e[0m"
echo -e "\e[1;33m1. Die Firewall die Ports 80 und 443 freigibt.\e[0m"
echo -e "\e[1;33m2. Deine Domain korrekt auf die IP-Adresse des Servers zeigt.\e[0m"

read -p "Hast du die Ports und die Domain überprüft und sind sie korrekt? [y/n]: " confirmation

if [[ "$confirmation" =~ ^[Yy]$ ]]; then
  echo -e "\e[1;32mStarte den Stack...\e[0m"
  docker compose up -d
  echo -e "\e[1;32mDer Stack wurde gestartet.\e[0m"
else
  echo -e "\e[1;31mBitte überprüfe die Firewall und die Domain-Einstellungen, bevor du den Stack startest.\e[0m"
fi