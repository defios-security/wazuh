#!/bin/bash

# Script Name: wazuh-deploy
# Version: 0.0.1
# Author: irradiatedcircle
# Email: amelia@defios.co.uk
#        amelia@irradiatedcircle.dev
# Description: Automates the deployment and configuration of Wazuh.

VERSION=0.0.1
WAZUH_VERSION="v4.8.0"
WAZUH_PATH="$PWD/Wazuh"
LOG_FILE="/var/log/defios-wazuh-deployer.log"
BRANDING_FILE="$PWD/branding/config.json"

function show_help() {
  echo "Usage: $0 [-h | -d] {install|start|stop|changePasswords|setBranding|deploy|remove}"
  echo "  -h  Show this help message"
  echo "  -d  Enable debug mode"
}

# Function to generate a strong password
function generate_password() {
  local length=$1
  local letters="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  local numbers="0123456789"
  local symbols=".*+?-"
  local all_chars="${letters}${numbers}${symbols}"

  # Ensure at least one letter, one number, and one symbol
  local password
  password=$(dd if=/dev/urandom bs=1 count=$((length * 2)) 2>/dev/null | LC_ALL=C tr -dc "${letters}" | head -c 1)
  password+=$(dd if=/dev/urandom bs=1 count=$((length * 2)) 2>/dev/null | LC_ALL=C tr -dc "${numbers}" | head -c 1)
  password+=$(dd if=/dev/urandom bs=1 count=$((length * 2)) 2>/dev/null | LC_ALL=C tr -dc "${symbols}" | head -c 1)

  # Generate the remaining characters
  password+=$(dd if=/dev/urandom bs=1 count=$((length * 2)) 2>/dev/null | LC_ALL=C tr -dc "${all_chars}" | head -c $((length - 3)))

  # Shuffle the password to ensure randomness
  password=$(echo "$password" | fold -w1 | shuf | tr -d '\n')

  echo "$password"
}

# Function to hash a password using bcrypt
function bcrypt_hash() {
        local password=$1

        echo $(htpasswd -bnBC 12 "" $password | tr -d ':' | sed 's/$2y/$2a/')
}

# Function to log messages
function log_message() {
  local message="$1"
  echo "$(date +"%Y-%m-%d %H:%M:%S") $message" >> "$LOG_FILE"
}

# Function to install dependencies
function install_dependencies() {
  log_message "Installing dependencies..."
  if [[ $EUID -ne 0 ]]; then
    log_message "Error: This script must be run as root."
    echo "Error: This script must be run as root."
    exit 1
  fi

  sudo apt-get update > /dev/null 2>&1
  if ! sudo apt-get install -y apache2-utils > /dev/null 2>&1; then
    log_message "Error: Unable to install dependencies. Please check your internet connection and try again."
    echo "Error: Unable to install dependencies. Please check your internet connection and try again."
    exit 1
  fi

  if ! sudo apt-get install -y jq > /dev/null 2>&1; then
    log_message "Error: Unable to install dependencies. Please check your internet connection and try again."
    echo "Error: Unable to install dependencies. Please check your internet connection and try again."
    exit 1
  fi

  # Add more dependencies here as needed, with error checking
}

# Function to install Wazuh
function install() {
	log_message "Downloading Wazuh ${WAZUH_VERSION}..."
	printf "[*] Downloading Wazuh ${WAZUH_VERSION}...\n"
	if ! git clone -q https://github.com/wazuh/wazuh-docker.git -b $WAZUH_VERSION $WAZUH_PATH &>/dev/null; then
		log_message "Error: Unable to download Wazuh. Please check your internet connection and try again."
		echo "Error: Unable to download Wazuh. Please check your internet connection and try again."
		exit 1
	fi

	log_message "Generating indexer certificates..."
	printf "[*] Generating indexer certificates...\n"
	if ! sudo docker compose -f "${WAZUH_PATH}/single-node/generate-indexer-certs.yml" up; then
		log_message "Error: Unable to generate indexer certificates. Please check your docker installation and try again."
		echo "Error: Unable to generate indexer certificates. Please check your docker installation and try again."
		exit 1
	fi
	log_message "Installation complete."
	printf "[*] Complete\n\n"
}

# Function to change the default passwords
function changePasswords() {
	log_message "Changing default passwords..."
	echo "[*] Changing default passwords..."

	INDEXER_PASSWORD=$(generate_password 32)
	INDEXER_PASSWORD_HASH=$(bcrypt_hash $INDEXER_PASSWORD)
	ESCAPED_INDEXER_PASSWORD_HASH=$(echo "$INDEXER_PASSWORD_HASH" | sed 's/[&/\]/\\&/g')
	API_PASSWORD=$(generate_password 32)
	DASHBOARD_PASSWORD=$(generate_password 32)
	DASHBOARD_PASSWORD_HASH=$(bcrypt_hash $DASHBOARD_PASSWORD)
	ESCAPED_DASHBOARD_PASSWORD_HASH=$(echo "$DASHBOARD_PASSWORD_HASH" | sed 's/[&/\]/\\&/g')

	# Replace the password variables with the randomly generated ones
	sed -i "s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=${INDEXER_PASSWORD}|g" "${WAZUH_PATH}/single-node/docker-compose.yml"
	sed -i "/admin:/,/^[^[:space:]]/s/hash: .*$/hash: \'${ESCAPED_INDEXER_PASSWORD_HASH}\'/" "${WAZUH_PATH}/single-node/config/wazuh_indexer/internal_users.yml"
	sed -i "s|API_PASSWORD=.*|API_PASSWORD=${API_PASSWORD}|g" "${WAZUH_PATH}/single-node/docker-compose.yml"
	sed -i "s|password: .*|password: \'${API_PASSWORD}\'|" "${WAZUH_PATH}/single-node/config/wazuh_dashboard/wazuh.yml"
	sed -i "s|DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}|g" "${WAZUH_PATH}/single-node/docker-compose.yml"
	sed -i "/kibanaserver:/,/^[^[:space:]]/s/hash: .*$/hash: \'${ESCAPED_DASHBOARD_PASSWORD_HASH}\'/" "${WAZUH_PATH}/single-node/config/wazuh_indexer/internal_users.yml"

	log_message "Passwords changed successfully."
	echo ""
	echo " Credentials "
	echo "-------------"
	echo " Indexer   : admin          / ${INDEXER_PASSWORD}"
	if [ "$DEBUG" = "true" ]; then echo " Hash      :                / ${INDEXER_PASSWORD_HASH}"; fi
	if [ "$DEBUG" = "true" ]; then echo " Escaped   :                / ${ESCAPED_INDEXER_PASSWORD_HASH}"; fi
	if [ "$DEBUG" = "true" ]; then echo ""; fi
	echo " API       : wazuh-wui      / ${API_PASSWORD}"
	if [ "$DEBUG" = "true" ]; then echo ""; fi
	echo " Dashboard : kibanaserver   / ${DASHBOARD_PASSWORD}"
	if [ "$DEBUG" = "true" ]; then echo " Hash      :                / ${DASHBOARD_PASSWORD_HASH}"; fi
	if [ "$DEBUG" = "true" ]; then echo " Escaped   :                / ${ESCAPED_DASHBOARD_PASSWORD_HASH}"; fi
	echo ""
	printf "[*] Passwords replaced in docker-compose.yml\n\n"

}

# Function to set the branding
function setBranding() {
	log_message "Setting branding..."
	echo "[*] Setting branding..."
	
	# Check if branding.json exists
	if [ ! -f "$BRANDING_FILE" ]; then
		log_message "Error: Branding file '$BRANDING_FILE' not found. Please create it."
		echo "Error: Branding file '$BRANDING_FILE' not found. Please create it."
		exit 1
	fi

	# Parse branding.json
	branding_json=$(cat "$BRANDING_FILE")

	# Check if FQDN is present in branding.json
	FQDN=$(jq -r '.FQDN' <<< "$branding_json")
	if [ -z "$FQDN" ]; then
		log_message "FQDN not found in branding.json. Disabling branding."
		echo "[*] FQDN not found in branding.json. Disabling branding."
		return
	fi

	# Check for branding directory and docker-compose binding
	branding_dir="${WAZUH_PATH}/single-node/config/wazuh_dashboard/branding"
	if [ ! -d "$branding_dir" ]; then
		log_message "Branding directory not found. Creating it."
		echo "[!] Unable to find it, creating it now..."
		mkdir -p "$branding_dir"
	fi
	
	if grep -q '${WAZUH_PATH}/single-node/config/wazuh_dashboard/branding' "${WAZUH_PATH}/single-node/docker-compose.yml"; then
		log_message "Branding already configured. Skipping..."
		echo "[*] Already configured, skipping..."
	else
		log_message "Branding not found. Configuring..."
		echo "[*] Not found, configuring now..."
		if sed -i 's#wazuh-dashboard-custom:/usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom#./config/wazuh_dashboard/branding:/usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom/images#g' "${WAZUH_PATH}/single-node/docker-compose.yml"; then
			log_message "Branding configured successfully."
			echo "[*] Configured docker-compose.yml to mount branding directory."
		fi
	fi
	
	# Extract branding values
	logo_default_url=$(jq -r '.logo.defaultUrl' <<< "$branding_json")
	logo_dark_mode_url=$(jq -r '.logo.darkModeUrl' <<< "$branding_json")
	mark_default_url=$(jq -r '.mark.defaultUrl' <<< "$branding_json")
	mark_dark_mode_url=$(jq -r '.mark.darkModeUrl' <<< "$branding_json")
	loading_logo_default_url=$(jq -r '.loadingLogo.defaultUrl' <<< "$branding_json")
	loading_logo_dark_mode_url=$(jq -r '.loadingLogo.darkModeUrl' <<< "$branding_json")
	favicon_url=$(jq -r '.faviconUrl' <<< "$branding_json")
	application_title=$(jq -r '.applicationTitle' <<< "$branding_json")
	use_expanded_header=$(jq -r '.useExpandedHeader' <<< "$branding_json")
	
	# Configure branding in opensearch_dashboards.yml
	cat <<EOF >> "${WAZUH_PATH}/single-node/config/wazuh_dashboard/opensearch_dashboards.yml"
opensearchDashboards.branding:
   logo:
      defaultUrl: "$logo_default_url"
      darkModeUrl: "$logo_dark_mode_url"
   mark:
      defaultUrl: "$mark_default_url"
      darkModeUrl: "$mark_dark_mode_url"
   loadingLogo:
      defaultUrl: "$loading_logo_default_url"
      darkModeUrl: "$loading_logo_dark_mode_url"
   faviconUrl: "$favicon_url"
   applicationTitle: "$application_title"
   useExpandedHeader: $use_expanded_header
EOF

	# Configure branding in wazuh.yml
	cat <<EOF >> "${WAZUH_PATH}/single-node/config/wazuh_dashboard/wazuh.yml"
customization.logo.healthcheck: "custom/images/defios-logo-black.png"
customization.logo.app: "custom/images/defios-logo-black.png"
customization.logo.reports: "custom/images/defios-logo-black.png"
EOF

	log_message "Branding configured successfully."
	printf "[*] Branding configured.\n\n"
}

# Function to start Wazuh
function startWazuh() {
	log_message "Starting Wazuh..."
	sudo docker compose -f "${WAZUH_PATH}/single-node/docker-compose.yml" up -d 
	log_message "Wazuh started successfully."
}

# Function to stop Wazuh
function stopWazuh() {
	log_message "Stopping Wazuh..."
	sudo docker compose -f "${WAZUH_PATH}/single-node/docker-compose.yml" down
	log_message "Wazuh stopped successfully."
}

# Function to Wremove Wazuh
function remove() {
	log_message "Removing Wazuh..."
	echo "[*] Removing Wuzah..."
	sudo docker compose -f "${WAZUH_PATH}/single-node/generate-indexer-certs.yml" down -v
	sudo docker compose -f "${WAZUH_PATH}/single-node/docker-compose.yml" down -v
	sudo rm -rf $WAZUH_PATH
	log_message "Wazuh removed successfully."
	printf "[*] Removal complete...\n\n"
}

# Install dependencies silently
install_dependencies

echo ""
echo "    .___      _____.__                   "
echo "  __| _/_____/ ____\__| ____  ______     "
echo " / __ |/ __ \   __\|  |/  _ \/  ___/     "
echo "/ /_/ \  ___/|  |  |  (  <_> )___ \      "
echo "\____ |\___  >__|  |__|\____/____  >_____"
echo "     \/    \/                    \/_____/"
echo "::wazuh-deploy v${VERSION}"
echo ""

# Parse arguments using getopts
while getopts ":hd" opt; do
  case $opt in
    h)
      show_help
      exit 0
      ;;
    d)
      DEBUG=true
      printf "[!] Debug mode enabled, happy hunting <3\n\n"
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      exit 1
      ;;
  esac
done

shift $((OPTIND - 1))

# Handle commands
case "$1" in
  "install")
    install
    ;;
  "changePasswords")
    changePasswords
    ;;
  "setBranding")
    setBranding
    ;;
  "deploy")
    install
    changePasswords
    setBranding
    ;;
  "start")
    startWazuh
    ;;
  "stop")
    stopWazuh
    ;;
  "remove")
    remove
    ;;
  *)
    show_help
    exit 1
    ;;
esac
