#!/bin/bash

# Farben für die Ausgabe
green='\033[0;32m'
yellow='\033[1;33m'
red='\033[0m'
nc='\033[0m' # Kein Farbcode

# Funktion zum Ausgeben eines Schritts
show_step() {
    echo -e "${yellow}[$1/$2] $3...${nc}"
}

# Funktion zum Anzeigen, dass ein Schritt abgeschlossen ist
step_done() {
    echo -e "${green}✓ $1 abgeschlossen${nc}"
}

# Gesamtschritte für das Skript festlegen
total_steps=18
current_step=1

# Setze das Arbeitsverzeichnis auf das Verzeichnis, in dem das Skript liegt
show_step $current_step $total_steps "Setze Arbeitsverzeichnis"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd "$SCRIPT_DIR" || exit
step_done "Arbeitsverzeichnis gesetzt"
((current_step++))

# Überprüfen, ob das Skript mit Root-Rechten ausgeführt wird
show_step $current_step $total_steps "Überprüfen von Root-Rechten"
if [ "$EUID" -ne 0 ]; then
  echo -e "${red}Bitte führe das Skript mit Root-Rechten aus.${nc}"
  exit 1
fi
step_done "Root-Rechte überprüft"
((current_step++))

# Überprüfen, ob Docker installiert ist
show_step $current_step $total_steps "Überprüfen von Docker"
if ! command -v docker &> /dev/null; then
  echo -e "${red}Docker ist nicht installiert. Bitte folge der Anleitung unter: https://docs.docker.com/engine/install/${nc}"
  exit 1
fi
step_done "Docker installiert"
((current_step++))

# Überprüfen, ob Docker Compose installiert ist
show_step $current_step $total_steps "Überprüfen von Docker Compose"
if ! command -v docker compose &> /dev/null; then
  echo -e "${red}Docker Compose ist nicht installiert. Bitte folge der Anleitung unter: https://docs.docker.com/engine/install/${nc}"
  exit 1
fi
step_done "Docker Compose installiert"
((current_step++))

# Installiere apache2-utils, falls nicht vorhanden
show_step $current_step $total_steps "Installiere apache2-utils, falls erforderlich"
command -v htpasswd >/dev/null 2>&1 || { sudo apt update && sudo apt install -y apache2-utils; }
step_done "apache2-utils installiert"
((current_step++))

# Überprüfen, ob Container laufen
show_step $current_step $total_steps "Überprüfen von laufenden Containern"
containers=("crowdsec" "socket-proxy" "traefik" "traefik_crowdsec_bouncer")
for container in "${containers[@]}"; do
  if [ "$(docker ps -q -f name=$container)" ]; then
    echo -e "${red}Der Docker-Container '$container' läuft bereits. Das Skript wird abgebrochen.${nc}"
    exit 1
  fi
done
step_done "Keine laufenden Container gefunden"
((current_step++))

# Netzwerke überprüfen
show_step $current_step $total_steps "Überprüfen von Netzwerken"
networks=("proxy" "socket_proxy" "crowdsec")
for network in "${networks[@]}"; do
  if [ "$(docker network ls -q -f name=^${network}$)" ]; then
    echo -e "${red}Das Docker-Netzwerk '$network' existiert bereits. Das Skript wird abgebrochen.${nc}"
    exit 1
  fi
done
step_done "Keine bestehenden Netzwerke gefunden"
((current_step++))

# Dateien kopieren
show_step $current_step $total_steps "Kopiere erforderliche Dateien"
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

# Dateien kopieren oder das Skript beenden, wenn eine .sample Datei fehlt
for file_pair in "${files_to_copy[@]}"; do
  src=$(echo $file_pair | awk '{print $1}')
  dst=$(echo $file_pair | awk '{print $2}')

  src_path="${SCRIPT_DIR}/${src}"
  dst_path="${SCRIPT_DIR}/${dst}"

  if [ -f "$src_path" ]; then
    cp "$src_path" "$dst_path"
    echo "Kopiere ${src_path} nach ${dst_path}"
  else
    echo -e "${red}Die Datei ${src_path} existiert nicht. Das Skript wird abgebrochen.${nc}"
    exit 1
  fi
done

sudo chmod 600 data/traefik/certs/acme_letsencrypt.json
sudo chmod 600 data/traefik/certs/tls_letsencrypt.json

step_done "Dateien kopiert und Rechte gesetzt"
((current_step++))

# Benutzerabfrage mit y/n und Standardwert 'n' für das CrowdSec-Repository
show_step $current_step $total_steps "Überprüfung: CrowdSec-Repository"

# Frage den Benutzer, ob das CrowdSec-Repository bereits installiert ist, Standardwert 'n'
read -p "Ist das CrowdSec-Repository bereits in deinen Paketquellen vorhanden? [y/n, Standard: n]: " has_crowdsec_repo
has_crowdsec_repo=${has_crowdsec_repo:-n}  # Standardwert n setzen
has_crowdsec_repo=$(echo "$has_crowdsec_repo" | tr '[:upper:]' '[:lower:]')  # Eingabe in Kleinbuchstaben umwandeln

# Prüfen, ob das Repository installiert werden muss
if [ "$has_crowdsec_repo" == "y" ]; then
  echo "Das CrowdSec-Repository ist bereits vorhanden. Installation wird übersprungen."
else
  echo "Das CrowdSec-Repository wird installiert..."
  curl -s https://install.crowdsec.net | sudo sh
  echo "CrowdSec-Repository erfolgreich installiert."
fi

# Schritt abgeschlossen
step_done "CrowdSec-Repository überprüft und ggf. installiert"
((current_step++))

# Installiere openssl, falls nicht vorhanden
show_step $current_step $total_steps "Überprüfen von OpenSSL"
command -v openssl >/dev/null 2>&1 || { sudo apt update && sudo apt install -y openssl; }
step_done "OpenSSL überprüft"
((current_step++))

# Bouncer-Passwörter generieren
show_step $current_step $total_steps "Generiere Bouncer-Passwörter"
BOUNCER_KEY_TRAEFIK_PASSWORD=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#$%^&*()-_=+[]{}<>?|')
echo -e "\nBOUNCER_KEY_TRAEFIK=$BOUNCER_KEY_TRAEFIK_PASSWORD" >> ${SCRIPT_DIR}/.env
sleep 3
BOUNCER_KEY_FIREWALL_PASSWORD=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#$%^&*()-_=+[]{}<>?|')
echo "BOUNCER_KEY_FIREWALL=$BOUNCER_KEY_FIREWALL_PASSWORD" >> ${SCRIPT_DIR}/.env
step_done "Bouncer-Passwörter generiert"
((current_step++))

# E-Mail-Adresse für SSL-Zertifikate
show_step $current_step $total_steps "Frage nach E-Mail-Adresse für SSL-Zertifikate"

# Funktion zur E-Mail-Validierung
validate_email() {
  local email_regex="^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
  if [[ $1 =~ $email_regex ]]; then
    return 0  # gültige E-Mail
  else
    return 1  # ungültige E-Mail
  fi
}

# Benutzer nach E-Mail-Adresse fragen und diese bestätigen
while true; do
  read -p "Bitte gib deine E-Mail-Adresse für die SSL-Zertifikate ein: " ssl_email
  if validate_email "$ssl_email"; then
    echo "Gültige E-Mail-Adresse eingegeben: $ssl_email"

    # Bestätigung der E-Mail-Adresse mit y/n (Standard: y)
    read -p "Möchtest du diese E-Mail-Adresse verwenden? ($ssl_email) [y/n, Standard: y]: " confirm_email
    confirm_email=${confirm_email:-y}  # Standardwert auf 'y' setzen
    confirm_email=$(echo "$confirm_email" | tr '[:upper:]' '[:lower:]')  # In Kleinbuchstaben umwandeln

    if [ "$confirm_email" == "y" ]; then
      echo "E-Mail-Adresse wurde bestätigt: $ssl_email"
      break
    else
      echo -e "\e[31mE-Mail-Adresse wurde nicht bestätigt. Bitte gib eine neue E-Mail-Adresse ein.\e[0m"
    fi
  else
    echo -e "\e[31mUngültige E-Mail-Adresse. Bitte versuche es erneut.\e[0m"
  fi
done

# Überprüfen, ob die Traefik-Konfigurationsdatei existiert
traefik_config_file="data/traefik/traefik.yml"
if [ ! -f "$traefik_config_file" ]; then
  echo -e "\e[31mDie Datei $traefik_config_file existiert nicht. Das Skript wird abgebrochen.\e[0m"
  exit 1
fi

# E-Mail-Adresse in der traefik.yml Datei setzen
sed -i "s/email: \".*\"/email: \"$ssl_email\"/g" "$traefik_config_file"

# Schritt abgeschlossen
step_done "SSL-Zertifikat E-Mail-Adresse gesetzt"
((current_step++))

# Wunsch-Domain für Traefik-Dashboard
show_step $current_step $total_steps "Frage nach Wunsch-Domain für Traefik-Dashboard"

# Überprüfen, ob die .env-Datei existiert
env_file="${SCRIPT_DIR}/.env"
if [ ! -f "$env_file" ]; then
  echo -e "\e[31mDie Datei $env_file existiert nicht. Das Skript wird abgebrochen.\e[0m"
  exit 1
fi

# Funktion zur Validierung der Domain ohne http/https und ohne Slash
validate_domain() {
  local domain_regex="^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$"
  if [[ $1 =~ $domain_regex ]]; then
    return 0  # Gültige Domain
  else
    return 1  # Ungültige Domain
  fi
}

# Benutzer nach der Wunsch-Domain fragen
while true; do
  read -p "Bitte gib die Wunsch-Domain für dein Traefik-Dashboard ein (ohne http/https und ohne '/'): " dashboard_domain

  # Entferne mögliche "http://", "https://", und Slashes am Anfang und Ende
  dashboard_domain=$(echo "$dashboard_domain" | sed -e 's|^http[s]\?://||' -e 's|/$||')

  # Überprüfen, ob das Format der Domain korrekt ist
  if validate_domain "$dashboard_domain"; then
    # Bestätigung der Domain mit y/n (Standard: y)
    read -p "Möchtest du diese Domain verwenden? ($dashboard_domain) [y/n, Standard: y]: " confirm_domain
    confirm_domain=${confirm_domain:-y}  # Standardwert auf 'y' setzen
    confirm_domain=$(echo "$confirm_domain" | tr '[:upper:]' '[:lower:]')  # In Kleinbuchstaben umwandeln

    if [ "$confirm_domain" == "y" ]; then
      echo "Domain wurde bestätigt: $dashboard_domain"
      break
    else
      echo -e "\e[31mDomain wurde nicht bestätigt. Bitte gib eine neue Domain ein.\e[0m"
    fi
  else
    echo -e "\e[31mUngültiges Domain-Format. Bitte versuche es erneut.\e[0m"
  fi
done

# Wunsch-Domain in der .env-Datei setzen
sed -i "s/SERVICES_TRAEFIK_LABELS_TRAEFIK_HOST=.*/SERVICES_TRAEFIK_LABELS_TRAEFIK_HOST=HOST(\`$dashboard_domain\`)/" "$env_file"
echo "" >> "$env_file"  # Leere Zeile hinzufügen, um korrektes Layout zu gewährleisten

# Schritt abgeschlossen
step_done "Traefik-Domain gesetzt"
((current_step++))

# CrowdSec und Firewall-Konfiguration
show_step $current_step $total_steps "CrowdSec einmalig starten und herunterfahren"
docker compose up crowdsec -d && docker compose down
step_done "CrowdSec gestartet und heruntergefahren"
((current_step++))

show_step $current_step $total_steps "CrowdSec Konfiguration anpassen"
acquis_file="${SCRIPT_DIR}/data/crowdsec/config/acquis.yaml"
if [ ! -f "$acquis_file" ]; then
  echo -e "${red}Die Datei $acquis_file existiert nicht. Das Skript wird abgebrochen.${nc}"
  exit 1
fi

cat <<EOL > "$acquis_file"
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
EOL

step_done "acquis.yaml bearbeitet"
((current_step++))

# Firewall-Auswahl
show_step $current_step $total_steps "Firewall-Bouncer installieren"
echo "Welche Firewall verwendest du?"
echo "1) UFW"
echo "2) iptables"
echo "3) nftables"
read -p "Bitte wähle die Nummer deiner Firewall (1-3): " firewall_choice

case $firewall_choice in
  1)
    echo "UFW erkannt. Installiere crowdsec-firewall-bouncer-iptables..."
    sudo apt install -y crowdsec-firewall-bouncer-iptables
    ;;
  2)
    echo "iptables erkannt. Installiere crowdsec-firewall-bouncer-iptables..."
    sudo apt install -y crowdsec-firewall-bouncer-iptables
    ;;
  3)
    echo "nftables erkannt. Installiere crowdsec-firewall-bouncer-nftables..."
    sudo apt install -y crowdsec-firewall-bouncer-nftables
    ;;
  *)
    echo -e "${red}Ungültige Auswahl. Das Skript wird abgebrochen.${nc}"
    exit 1
    ;;
esac
step_done "Firewall-Bouncer installiert"
((current_step++))

show_step $current_step $total_steps "Firewall-Bouncer Konfiguration anpassen"
firewall_bouncer_config="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
if [ ! -f "$firewall_bouncer_config" ]; then
  echo -e "${red}Die Datei $firewall_bouncer_config existiert nicht. Das Skript wird abgebrochen.${nc}"
  exit 1
fi

# Setze die api_url und den api_key in der crowdsec-firewall-bouncer.yaml
sudo sed -i "s#api_url: .*#api_url: http://172.31.127.254:8080/#g" "$firewall_bouncer_config"
sudo sed -i "s#api_key: .*#api_key: $BOUNCER_KEY_FIREWALL_PASSWORD#g" "$firewall_bouncer_config"
sudo systemctl enable crowdsec-firewall-bouncer
sudo systemctl restart crowdsec-firewall-bouncer
step_done "Firewall-Bouncer angepasst"
((current_step++))

# Dashboard-Benutzer erstellen
show_step $current_step $total_steps "Erstelle Benutzer für Traefik-Dashboard"
read -p "Bitte gib den gewünschten Benutzernamen für das Dashboard ein: " dashboard_user
htpasswd_file="/opt/containers/traefik-crowdsec-stack/data/traefik/.htpasswd"
sudo htpasswd -c "$htpasswd_file" "$dashboard_user"
step_done "Dashboard-Benutzer erstellt"
((current_step++))

# Letzter Hinweis und Stack starten
show_step $current_step $total_steps "Finale Überprüfung der Firewall und Domain"
read -p "Hast du die Ports und die Domain überprüft und sind sie korrekt? [y/n, Standard: n]: " confirmation
confirmation=${confirmation:-n}  # Setzt Standardwert auf 'n', wenn keine Eingabe erfolgt

if [[ "$confirmation" =~ ^[Yy]$ ]]; then
  echo "Starte den Stack..."
  docker compose up -d
  step_done "Stack gestartet"
else
  echo -e "${red}Bitte überprüfe die Firewall und die Domain-Einstellungen, bevor du den Stack startest.${nc}"
fi