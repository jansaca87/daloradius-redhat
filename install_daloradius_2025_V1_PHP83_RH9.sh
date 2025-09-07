#!/bin/bash

# daloRADIUS - RADIUS Web Platform with Enhanced Security for RHEL 9.6
# Enhanced version with FreeRADIUS 3.2 from NetworkRADIUS, PHP 8.3, HTTPS, and CIS Security Hardening

# Set default values for variables
ENABLE_COLORS=true
DB_HOST=localhost
DB_PORT=3306
DALORADIUS_USERS_PORT=443
DALORADIUS_OPERATORS_PORT=8443
DALORADIUS_ROOT_DIRECTORY=/var/www/daloradius
DALORADIUS_CONF_FILE="${DALORADIUS_ROOT_DIRECTORY}/app/common/includes/daloradius.conf.php"
DALORADIUS_SERVER_ADMIN=admin@example.com
FREERADIUS_SQL_MOD_PATH="/etc/raddb/mods-available/sql"

# SSL Certificate Configuration
CERT_COUNTRY="US"
CERT_STATE="California"
CERT_CITY="San Francisco"
CERT_ORGANIZATION="Example Corp"
CERT_ORGANIZATIONAL_UNIT="IT"
CERT_COMMON_NAME="radius.example.com"
CERT_EMAIL="admin@example.com"

# Color functions
print_green() {
    echo -e "${GREEN}$1${NC}"
}

print_red() {
    echo -e "${RED}$1${NC}"
}

print_yellow() {
    echo -e "${YELLOW}$1${NC}"
}

print_blue() {
    echo -e "${BLUE}$1${NC}"
}

print_spinner() {
    PID=$1
    i=1
    sp="/-\|"
    echo -n ' '
    while [ -d /proc/$PID ]; do
        printf "\b${sp:i++%${#sp}:1}"
        sleep 0.1
    done
    printf "\b"
}

# MariaDB configuration functions
mariadb_init_conf() {
    echo -n "[+] Initializing MariaDB configuration... "
    MARIADB_CLIENT_FILENAME="$(mktemp -qu).conf"
    if ! cat << EOF > "${MARIADB_CLIENT_FILENAME}"
[client]
database=${DB_SCHEMA}
host=${DB_HOST}
port=${DB_PORT}
user=${DB_USER}
password=${DB_PASS}
EOF
    then
        print_red "KO"
        echo "[!] Failed to initialize MariaDB configuration. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

mariadb_clean_conf() {
    echo -n "[+] Cleaning up MariaDB configuration... "
    if [ -e "${MARIADB_CLIENT_FILENAME}" ]; then
        rm -rf "${MARIADB_CLIENT_FILENAME}"
    fi
    print_green "OK"
}

# Function to generate a random string of specified length
generate_random_string() {
    local length="$1"
    cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c"$length"
}

# Function to ensure the script is run as root
system_ensure_root() {
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            print_red "[!] This script needs to be run as root. Elevating script to root with sudo."
            interpreter="$(head -1 "$0" | cut -c 3-)"
            if [ -x "$interpreter" ]; then
                sudo "$interpreter" "$0" "$@"
            else
                sudo "$0" "$@"
            fi
            exit $?
        else
            print_red "[!] This script needs to be run as root."
            exit 1
        fi
    fi
}

# Function to install necessary system packages and perform system update
system_update() {
    echo -n "[+] Updating system package lists... "
    dnf update -y >/dev/null 2>&1 & print_spinner $!
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to update package lists. Aborting." >&2
        exit 1
    fi
    print_green "OK"
    
    echo -n "[+] Installing EPEL repository... "
    dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm -y >/dev/null 2>&1 & print_spinner $!
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to install EPEL repository. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to install MariaDB
mariadb_install() {
    echo -n "[+] Installing MariaDB... "
    dnf install -y mariadb-server mariadb >/dev/null 2>&1 & print_spinner $!
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to install MariaDB. Aborting." >&2
        exit 1
    fi
    print_green "OK"
    
    echo -n "[+] Starting and enabling MariaDB... "
    systemctl enable --now mariadb >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to start MariaDB. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to secure MariaDB installation
mariadb_secure() {
    echo -n "[+] Securing MariaDB... "
    if ! mariadb -u root <<SQL >/dev/null 2>&1
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
ALTER USER root@'localhost' IDENTIFIED BY '';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQL
    then
        print_red "KO"
        echo "[!] Failed to secure MariaDB. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to initialize MariaDB database and user
mariadb_db_init() {
    echo -n "[+] Initializing MariaDB database and user... "
    if ! mariadb -u root <<SQL >/dev/null 2>&1
CREATE DATABASE ${DB_SCHEMA};
GRANT ALL ON ${DB_SCHEMA}.* TO '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
FLUSH PRIVILEGES;
SQL
    then
        print_red "KO"
        echo "[!] Failed to init MariaDB. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to install FreeRADIUS from NetworkRADIUS repository
freeradius_install() {
    echo -n "[+] Adding NetworkRADIUS repository... "
    
    # Import PGP key
    rpm --import 'https://packages.inkbridgenetworks.com/pgp/packages.networkradius.com.asc' >/dev/null 2>&1
    
    # Add repository
    cat <<'EOF' >/etc/yum.repos.d/networkradius.repo
[networkradius]
name=NetworkRADIUS-$releasever
baseurl=http://packages.inkbridgenetworks.com/freeradius-3.2/rocky/$releasever/
enabled=1
gpgcheck=1
gpgkey=https://packages.inkbridgenetworks.com/pgp/packages.networkradius.com.asc
EOF
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to add NetworkRADIUS repository. Aborting." >&2
        exit 1
    fi
    print_green "OK"
    
    echo -n "[+] Enabling Code Ready Builder repository... "
    dnf install -y yum-utils >/dev/null 2>&1
	subscription-manager repos --enable codeready-builder-for-rhel-9-x86_64-rpms >/dev/null 2>&1
    #dnf config-manager --enable crb >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to enable CRB repository. Aborting." >&2
        exit 1
    fi
    print_green "OK"
    
    echo -n "[+] Installing FreeRADIUS 3.2 from NetworkRADIUS... "
    dnf install -y freeradius freeradius-mysql freeradius-utils >/dev/null 2>&1 & print_spinner $!
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to install FreeRADIUS. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to set up freeRADIUS SQL module
freeradius_setup_sql_mod() {
    echo -n "[+] Setting up freeRADIUS SQL module... "
    if ! sed -Ei '/^[\t\s#]*tls\s+\{/, /[\t\s#]*\}/ s/^/#/' "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! sed -Ei 's/^[\t\s#]*dialect\s+=\s+.*$/\tdialect = "mysql"/g' "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! sed -Ei 's/^[\t\s#]*driver\s+=\s+"rlm_sql_null"/\tdriver = "rlm_sql_\${dialect}"/g' "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! sed -Ei "s/^[\t\s#]*server\s+=\s+\"localhost\"/\tserver = \"${DB_HOST}\"/g" "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! sed -Ei "s/^[\t\s#]*port\s+=\s+[0-9]+/\tport = ${DB_PORT}/g" "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! sed -Ei "s/^[\t\s#]*login\s+=\s+\"radius\"/\tlogin = \"${DB_USER}\"/g" "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! sed -Ei "s/^[\t\s#]*password\s+=\s+\"radpass\"/\tpassword = \"${DB_PASS}\"/g" "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! sed -Ei "s/^[\t\s#]*radius_db\s+=\s+\"radius\"/\tradius_db = \"${DB_SCHEMA}\"/g" "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! sed -Ei 's/^[\t\s#]*read_clients\s+=\s+.*$/\tread_clients = yes/g' "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! sed -Ei 's/^[\t\s#]*client_table\s+=\s+.*$/\tclient_table = "nas"/g' "${FREERADIUS_SQL_MOD_PATH}" >/dev/null 2>&1 || \
       ! ln -s "${FREERADIUS_SQL_MOD_PATH}" /etc/raddb/mods-enabled/ >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to set up freeRADIUS SQL module. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to import FreeRADIUS SQL schema
freeradius_import_schema() {
    echo -n "[+] Importing FreeRADIUS SQL schema... "
    FREERADIUS_SCHEMA_PATH="/etc/raddb/mods-config/sql/main/mysql/schema.sql"
    if [ -f "${FREERADIUS_SCHEMA_PATH}" ]; then
        mariadb --defaults-extra-file="${MARIADB_CLIENT_FILENAME}" < "${FREERADIUS_SCHEMA_PATH}" >/dev/null 2>&1 & print_spinner $!
        if [ $? -ne 0 ]; then
            print_red "KO"
            echo "[!] Failed to import FreeRADIUS SQL schema. Aborting." >&2
            exit 1
        fi
    else
        print_yellow "SKIP - Schema file not found"
    fi
    print_green "OK"
}

# Function to restart freeRADIUS service
freeradius_enable_restart() {
    echo -n "[+] Enabling and restarting freeRADIUS... "
    if ! systemctl enable radiusd.service >/dev/null 2>&1 || ! systemctl restart radiusd.service >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to enable and restart freeRADIUS. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to install PHP 8.3 and daloRADIUS dependencies
daloradius_install_dep() {
    echo -n "[+] Installing Remi repository for PHP 8.3... "
    
    # Install Remi repository
    dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm >/dev/null 2>&1 & print_spinner $!
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to install Remi repository. Aborting." >&2
        exit 1
    fi
    print_green "OK"
    
    echo -n "[+] Enabling PHP 8.3 module... "
    
    # Reset and enable PHP 8.3 module
    dnf module reset php -y >/dev/null 2>&1
    dnf module enable php:8.3 -y >/dev/null 2>&1 & print_spinner $!
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to enable PHP 8.3 module. Aborting." >&2
        exit 1
    fi
    print_green "OK"
    
    echo -n "[+] Installing PHP 8.3 and dependencies... "
    
    # Install Apache, PHP 8.3 and required extensions
    dnf install -y httpd php php-mysqlnd php-zip php-mbstring php-common php-curl php-gd php-json \
                   php-xml php-cli git rsyslog openssl fail2ban mod_ssl >/dev/null 2>&1
	dnf install -y php-pear >/dev/null 2>&1
	pear channel-update pear.php.net >/dev/null 2>&1
	pear install DB >/dev/null 2>&1
	pear install Mail >/dev/null 2>&1
	pear install Mail_Mime >/dev/null 2>&1 & print_spinner $!
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to install PHP 8.3 and dependencies. Aborting." >&2
        exit 1
    fi
    print_green "OK"
    
    echo -n "[+] Verifying PHP 8.3 installation... "
    PHP_VERSION=$(php -v | head -n 1 | grep -o "PHP 8\.3\.[0-9]*")
    if [[ "$PHP_VERSION" =~ ^PHP\ 8\.3\.[0-9]+$ ]]; then
        print_green "OK - $PHP_VERSION installed"
    else
        print_red "KO"
        echo "[!] PHP 8.3 not properly installed. Found: $(php -v | head -n 1)" >&2
        exit 1
    fi
}

# Function to configure firewall
configure_firewall() {
    echo -n "[+] Configuring firewall... "
    
    # Enable and start firewalld
    systemctl enable --now firewalld >/dev/null 2>&1
    
    # Open required ports
    firewall-cmd --permanent --add-port=${DALORADIUS_USERS_PORT}/tcp >/dev/null 2>&1
    firewall-cmd --permanent --add-port=${DALORADIUS_OPERATORS_PORT}/tcp >/dev/null 2>&1
    firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
    firewall-cmd --permanent --add-port=8000/tcp >/dev/null 2>&1
    firewall-cmd --permanent --add-port=1812/udp >/dev/null 2>&1
    firewall-cmd --permanent --add-port=1813/udp >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to configure firewall. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to configure SELinux
configure_selinux() {
    echo -n "[+] Installing SELinux policy tools... "
    dnf install -y policycoreutils-python-utils >/dev/null 2>&1 & print_spinner $!
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to install SELinux tools. Aborting." >&2
        exit 1
    fi
    print_green "OK"
    
    echo -n "[+] Configuring SELinux booleans for Apache... "
    # Set correct SELinux booleans for RHEL 9
    setsebool -P httpd_enable_cgi 1 >/dev/null 2>&1
    setsebool -P httpd_execmem 1 >/dev/null 2>&1
    setsebool -P httpd_can_network_connect 1 >/dev/null 2>&1
    setsebool -P httpd_can_network_connect_db 1 >/dev/null 2>&1
    setsebool -P httpd_read_user_content 1 >/dev/null 2>&1
    print_green "OK"
    
    echo -n "[+] Adding custom ports to SELinux... "
    # Add custom ports to SELinux (use -m if port already exists)
    semanage port -a -t http_port_t -p tcp 8000 >/dev/null 2>&1 || \
    semanage port -m -t http_port_t -p tcp 8000 >/dev/null 2>&1
    
    semanage port -a -t http_port_t -p tcp 8443 >/dev/null 2>&1 || \
    semanage port -m -t http_port_t -p tcp 8443 >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to configure SELinux ports. Checking current status..." >&2
        semanage port -l | grep http_port_t | grep -E "(8000|8443)"
        echo "[!] Continuing with installation..." >&2
    fi
    print_green "OK"
    
    echo -n "[+] Setting SELinux contexts for daloRADIUS... "
    # Set proper SELinux contexts for daloRADIUS directory
    if [ -d "${DALORADIUS_ROOT_DIRECTORY}" ]; then
        restorecon -Rv "${DALORADIUS_ROOT_DIRECTORY}" >/dev/null 2>&1
        chcon -R -t httpd_sys_content_t "${DALORADIUS_ROOT_DIRECTORY}" >/dev/null 2>&1
        
        # Set specific context for configuration file
        chcon -t httpd_config_t "${DALORADIUS_ROOT_DIRECTORY}/app/common/includes/daloradius.conf.php" >/dev/null 2>&1
    fi
    
    # Fix Apache configuration files context
    restorecon -R /etc/httpd/ >/dev/null 2>&1
    
    print_green "OK"
}

configure_selinux_for_daloradius() {
    echo -n "[+] Installing SELinux policy tools... "
    dnf install -y policycoreutils-python-utils setroubleshoot-server >/dev/null 2>&1 & print_spinner $!
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to install SELinux tools. Aborting." >&2
        exit 1
    fi
    print_green "OK"
    
    echo -n "[+] Configuring SELinux booleans for DaloRADIUS... "
    # Booleans esenciales para DaloRADIUS
    setsebool -P httpd_enable_cgi 1 >/dev/null 2>&1
    setsebool -P httpd_execmem 1 >/dev/null 2>&1
    setsebool -P httpd_can_network_connect 1 >/dev/null 2>&1
    setsebool -P httpd_can_network_connect_db 1 >/dev/null 2>&1
    setsebool -P httpd_read_user_content 1 >/dev/null 2>&1
    setsebool -P httpd_anon_write 1 >/dev/null 2>&1
    setsebool -P httpd_can_sendmail 1 >/dev/null 2>&1
    setsebool -P httpd_unified 1 >/dev/null 2>&1
    print_green "OK"
    
    echo -n "[+] Adding custom ports to SELinux... "
    # Agregar puertos personalizados
    semanage port -a -t http_port_t -p tcp 8000 >/dev/null 2>&1 || \
    semanage port -m -t http_port_t -p tcp 8000 >/dev/null 2>&1
    
    semanage port -a -t http_port_t -p tcp 8443 >/dev/null 2>&1 || \
    semanage port -m -t http_port_t -p tcp 8443 >/dev/null 2>&1
    print_green "OK"
    
    echo -n "[+] Setting SELinux contexts for DaloRADIUS... "
    # Contextos para daloRADIUS
    restorecon -Rv "${DALORADIUS_ROOT_DIRECTORY}" >/dev/null 2>&1
    chcon -R -t httpd_sys_content_t "${DALORADIUS_ROOT_DIRECTORY}" >/dev/null 2>&1
    
    # Contextos específicos para funcionalidad
    chcon -R -t httpd_sys_script_exec_t "${DALORADIUS_ROOT_DIRECTORY}/app/" >/dev/null 2>&1
    chcon -t httpd_config_t "${DALORADIUS_ROOT_DIRECTORY}/app/common/includes/daloradius.conf.php" >/dev/null 2>&1
    
    # Contextos para FreeRADIUS
    chcon -R -t radiusd_etc_t /etc/raddb/ >/dev/null 2>&1
    chcon -R -t radiusd_log_t /var/log/radius/ >/dev/null 2>&1
    print_green "OK"
    
    echo -n "[+] Creating custom SELinux policy for service management... "
    # Crear política personalizada
    cat > /tmp/daloradius_selinux.te << 'EOF'
module daloradius_selinux 1.0;

require {
    type httpd_t;
    type systemd_unit_file_t;
    type radiusd_t;
    type radiusd_etc_t;
    type radiusd_var_run_t;
    type mysqld_t;
    type sshd_t;
    type init_t;
    class file { read write execute getattr };
    class dir { read search };
    class service { start stop status };
    class system { status };
    class capability { dac_override };
}

# Permitir que httpd verifique el estado de servicios
allow httpd_t systemd_unit_file_t:file read;
allow httpd_t init_t:system status;

# Permitir que httpd acceda a archivos de FreeRADIUS
allow httpd_t radiusd_etc_t:file { read write getattr };
allow httpd_t radiusd_etc_t:dir { read search };
allow httpd_t radiusd_var_run_t:file read;

# Permitir que httpd ejecute comandos del sistema
allow httpd_t self:capability dac_override;
EOF

    # Compilar e instalar política
    checkmodule -M -m -o /tmp/daloradius_selinux.mod /tmp/daloradius_selinux.te >/dev/null 2>&1
    semodule_package -o /tmp/daloradius_selinux.pp -m /tmp/daloradius_selinux.mod >/dev/null 2>&1
    semodule -i /tmp/daloradius_selinux.pp >/dev/null 2>&1
    
    # Limpiar archivos temporales
    rm -f /tmp/daloradius_selinux.* >/dev/null 2>&1
    print_green "OK"
    
    echo -n "[+] Configuring Apache user permissions... "
    # Agregar apache al grupo radiusd para acceso a logs
    usermod -a -G radiusd apache >/dev/null 2>&1
    
    # Permisos para logs del sistema
    chmod 644 /var/log/messages >/dev/null 2>&1
    chmod 755 /var/log/radius >/dev/null 2>&1
    chmod 644 /var/log/radius/*.log >/dev/null 2>&1 || true
    print_green "OK"
}

# Función para verificar configuración SELinux
verify_selinux_config() {
    echo -n "[+] Verifying SELinux configuration... "
    
    # Verificar booleans
    local booleans_ok=true
    for boolean in httpd_enable_cgi httpd_execmem httpd_can_network_connect httpd_can_network_connect_db; do
        if ! getsebool $boolean | grep -q "on"; then
            booleans_ok=false
            break
        fi
    done
    
    # Verificar puertos
    local ports_ok=true
    if ! semanage port -l | grep http_port_t | grep -q "8000\|8443"; then
        ports_ok=false
    fi
    
    if [ "$booleans_ok" = true ] && [ "$ports_ok" = true ]; then
        print_green "OK"
    else
        print_yellow "PARTIAL - Some configurations may need manual review"
    fi
}

# Function to install daloRADIUS
daloradius_installation() {
    SCRIPT_PATH=$(realpath $0)
    SCRIPT_DIR=$(dirname ${SCRIPT_PATH})
    
    if [ "${SCRIPT_DIR}" = "${DALORADIUS_ROOT_DIRECTORY}/setup" ]; then
        # local installation
        echo -n "[+] Setting up daloRADIUS... "
        if [ ! -f "${DALORADIUS_CONF_FILE}.sample" ]; then
            print_red "KO"
            echo "[!] daloRADIUS code seems to be corrupted. Aborting." >&2
            exit 1
        fi
    else
        # remote installation
        echo -n "[+] Downloading and setting up daloRADIUS... "
        if [ -d "${DALORADIUS_ROOT_DIRECTORY}" ]; then
            print_red "KO"
            echo "[!] Directory ${DALORADIUS_ROOT_DIRECTORY} already exists. Aborting." >&2
            exit 1
        fi
        
        git clone https://github.com/lirantal/daloradius.git "${DALORADIUS_ROOT_DIRECTORY}" >/dev/null 2>&1 & print_spinner $!
        if [ $? -ne 0 ]; then
            print_red "KO"
            echo "[!] Failed to clone daloRADIUS repository. Aborting." >&2
            exit 1
        fi
    fi
    print_green "OK"
}

# Function to create required directories for daloRADIUS
daloradius_setup_required_dirs() {
    echo -n "[+] Creating required directories for daloRADIUS... "
    if ! mkdir -p /var/log/httpd/daloradius/{operators,users} >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to create operators and users directories. Aborting." >&2
        exit 1
    fi
    
    if ! mkdir -p ${DALORADIUS_ROOT_DIRECTORY}/var/{log,backup} >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to create log and backup directories. Aborting." >&2
        exit 1
    fi
    
    if ! chown -R apache:apache ${DALORADIUS_ROOT_DIRECTORY}/var >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to change ownership of var directory. Aborting." >&2
        exit 1
    fi
    
    if ! chmod -R 775 ${DALORADIUS_ROOT_DIRECTORY}/var >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to change permissions of var directory. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to set up daloRADIUS configuration
daloradius_setup_required_files() {
    echo -n "[+] Setting up daloRADIUS configuration... "
    DALORADIUS_CONF_FILE="${DALORADIUS_ROOT_DIRECTORY}/app/common/includes/daloradius.conf.php"
    
    if ! cp "${DALORADIUS_CONF_FILE}.sample" "${DALORADIUS_CONF_FILE}" >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to copy sample configuration file. Aborting." >&2
        exit 1
    fi
    
    ( sed -Ei "s/^.*CONFIG_DB_HOST'\].*$/\$configValues['CONFIG_DB_HOST'] = '${DB_HOST}';/" "${DALORADIUS_CONF_FILE}" >/dev/null 2>&1 && \
      sed -Ei "s/^.*CONFIG_DB_PORT'\].*$/\$configValues['CONFIG_DB_PORT'] = '${DB_PORT}';/" "${DALORADIUS_CONF_FILE}" >/dev/null 2>&1 && \
      sed -Ei "s/^.*CONFIG_DB_USER'\].*$/\$configValues['CONFIG_DB_USER'] = '${DB_USER}';/" "${DALORADIUS_CONF_FILE}" >/dev/null 2>&1 && \
      sed -Ei "s/^.*CONFIG_DB_PASS'\].*$/\$configValues['CONFIG_DB_PASS'] = '${DB_PASS}';/" "${DALORADIUS_CONF_FILE}" >/dev/null 2>&1 && \
      sed -Ei "s/^.*CONFIG_DB_NAME'\].*$/\$configValues['CONFIG_DB_NAME'] = '${DB_SCHEMA}';/" "${DALORADIUS_CONF_FILE}" >/dev/null 2>&1 && \
      sed -Ei "s|^.*CONFIG_FILE_RADIUS_PROXY'\].*$|\$configValues['CONFIG_FILE_RADIUS_PROXY'] = '/etc/raddb/proxy.conf';|" "${DALORADIUS_CONF_FILE}" >/dev/null 2>&1 ) & \
    print_spinner $!
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to setup daloRADIUS configuration file. Aborting." >&2
        exit 1
    fi
    
    if ! chown apache:apache "${DALORADIUS_CONF_FILE}" >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to change ownership of configuration file. Aborting." >&2
        exit 1
    fi
    
    if ! chmod 664 "${DALORADIUS_CONF_FILE}" >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to change permissions of configuration file. Aborting." >&2
        exit 1
    fi
    
    if ! chown apache:apache ${DALORADIUS_ROOT_DIRECTORY}/contrib/scripts/dalo-crontab >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to change ownership of dalo-crontab script. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to set up log permissions for daloRADIUS
daloradius_setup_log_permissions() {
    echo -n "[+] Setting up log permissions for daloRADIUS... "
    
    # Give read permissions to syslog
    chmod 644 /var/log/messages >/dev/null 2>&1
    
    # Add apache to radiusd group to read FreeRADIUS logs
    usermod -a -G radiusd apache >/dev/null 2>&1
    
    # Ensure proper permissions for FreeRADIUS log directory
    chmod 755 /var/log/radius >/dev/null 2>&1
    chmod 644 /var/log/radius/*.log >/dev/null 2>&1
    
    print_green "OK"
}

# Function to generate SSL certificates
generate_ssl_certificates() {
    echo -n "[+] Generating SSL certificates... "
    SSL_DIR="/etc/ssl/daloradius"
    mkdir -p "${SSL_DIR}" >/dev/null 2>&1
    
    # Generate private key
    openssl genrsa -out "${SSL_DIR}/daloradius.key" 2048 >/dev/null 2>&1
    
    # Generate certificate signing request
    openssl req -new -key "${SSL_DIR}/daloradius.key" -out "${SSL_DIR}/daloradius.csr" -subj "/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_CITY}/O=${CERT_ORGANIZATION}/OU=${CERT_ORGANIZATIONAL_UNIT}/CN=${CERT_COMMON_NAME}/emailAddress=${CERT_EMAIL}" >/dev/null 2>&1
    
    # Generate self-signed certificate
    openssl x509 -req -days 365 -in "${SSL_DIR}/daloradius.csr" -signkey "${SSL_DIR}/daloradius.key" -out "${SSL_DIR}/daloradius.crt" >/dev/null 2>&1
    
    # Set proper permissions
    chmod 600 "${SSL_DIR}/daloradius.key" >/dev/null 2>&1
    chmod 644 "${SSL_DIR}/daloradius.crt" >/dev/null 2>&1
    chown root:root "${SSL_DIR}"/* >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to generate SSL certificates. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to generate default SSL certificates
generate_default_ssl_certificates() {
    echo -n "[+] Generating default SSL certificates for localhost... "
    
    # Create directories if they don't exist
    mkdir -p /etc/pki/tls/certs /etc/pki/tls/private >/dev/null 2>&1
    
    # Generate localhost certificate if it doesn't exist
    if [ ! -f /etc/pki/tls/certs/localhost.crt ] || [ ! -s /etc/pki/tls/certs/localhost.crt ]; then
        openssl req -newkey rsa:2048 -nodes \
            -keyout /etc/pki/tls/private/localhost.key \
            -x509 -days 365 \
            -out /etc/pki/tls/certs/localhost.crt \
            -subj '/CN=localhost' >/dev/null 2>&1
        
        if [ $? -ne 0 ]; then
            print_red "KO"
            echo "[!] Failed to generate localhost SSL certificate. Aborting." >&2
            exit 1
        fi
        
        # Set proper permissions
        chmod 600 /etc/pki/tls/private/localhost.key >/dev/null 2>&1
        chmod 644 /etc/pki/tls/certs/localhost.crt >/dev/null 2>&1
        chown root:root /etc/pki/tls/private/localhost.key >/dev/null 2>&1
        chown root:root /etc/pki/tls/certs/localhost.crt >/dev/null 2>&1
        
        # Restore SELinux contexts
        restorecon /etc/pki/tls/private/localhost.key >/dev/null 2>&1
        restorecon /etc/pki/tls/certs/localhost.crt >/dev/null 2>&1
    fi
    
    print_green "OK"
}

# Function to disable all Apache sites
apache_disable_all_sites() {
    echo -n "[+] Disabling default Apache configuration... "
    
    # Disable default welcome page
    if [ -f /etc/httpd/conf.d/welcome.conf ]; then
        mv /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/welcome.conf.disabled >/dev/null 2>&1
    fi
    
    # Disable autoindex
    if [ -f /etc/httpd/conf.d/autoindex.conf ]; then
        mv /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/autoindex.conf.disabled >/dev/null 2>&1
    fi
    
    print_green "OK"
}

# Function to apply Apache security hardening based on CIS benchmarks
apache_security_hardening() {
    echo -n "[+] Applying Apache security hardening... "
    
    # Create security configuration
    cat > /etc/httpd/conf.d/security-hardening.conf << 'EOF'
# Hide Apache version and OS information
ServerTokens Prod
ServerSignature Off

# Disable directory browsing
Options -Indexes

# Disable server-side includes and CGI execution
Options -Includes -ExecCGI

# Prevent access to .htaccess and other sensitive files
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# Prevent access to backup and temporary files
<FilesMatch "\.(bak|backup|swp|tmp)$">
    Require all denied
</FilesMatch>

# Security headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Timeout settings to prevent DoS attacks
Timeout 60
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 15

# Limit request size
LimitRequestBody 10485760
LimitRequestFields 100
LimitRequestFieldSize 1024
LimitRequestLine 512

# Disable unnecessary HTTP methods
<Location "/">
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Location>
EOF
    
    print_green "OK"
}

# Function to set up Apache ports for daloRADIUS
apache_setup_ports() {
    echo -n "[+] Cleaning Apache configuration conflicts... "
    
    # Backup original httpd.conf
    yes | cp -f /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.backup >/dev/null 2>&1
    
    # Remove any duplicate Listen directives from httpd.conf
    sed -i '/^Listen 443 ssl$/d' /etc/httpd/conf/httpd.conf >/dev/null 2>&1
    sed -i '/^Listen 8443 ssl$/d' /etc/httpd/conf/httpd.conf >/dev/null 2>&1
    sed -i '/^Listen 8000$/d' /etc/httpd/conf/httpd.conf >/dev/null 2>&1
    
	print_green "OK"
	
	echo -n "[+] Creating SSL ports configuration... "
	
	# Create SSL ports configuration
    cat > /etc/httpd/conf.d/ssl-ports.conf << 'EOF'
# Configuración de puertos SSL para DaloRADIUS
Listen 443 ssl
Listen 8443 ssl
EOF
    
    echo -n "[+] Creating daloRADIUS ports configuration... "
    
    # Create separate configuration file for daloRADIUS ports
    cat > /etc/httpd/conf.d/daloradius-ports.conf << EOF
# daloRADIUS custom ports
Listen 8000
EOF
    
    # Fix permissions and SELinux context
	chown root:root /etc/httpd/conf.d/ssl-ports.conf >/dev/null 2>&1
    chmod 644 /etc/httpd/conf.d/ssl-ports.conf >/dev/null 2>&1
    chown root:root /etc/httpd/conf.d/daloradius-ports.conf >/dev/null 2>&1
    chmod 644 /etc/httpd/conf.d/daloradius-ports.conf >/dev/null 2>&1
    restorecon /etc/httpd/conf.d/daloradius-ports.conf >/dev/null 2>&1
	restorecon /etc/httpd/conf.d/ssl-ports.conf >/dev/null 2>&1
	
	sed -i '5s/^Listen 443/#Listen 443/' /etc/httpd/conf.d/ssl.conf
    
    # Verify Apache configuration
    if ! httpd -t >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Apache configuration test failed. Removing custom ports..." >&2
        rm -f /etc/httpd/conf.d/daloradius-ports.conf
		rm -f /etc/httpd/conf.d/ssl-ports.conf
        exit 1
    fi
    
    print_green "OK"
}

# Function to configure SSL properly for Apache
apache_configure_ssl() {
    echo -n "[+] Configuring SSL for Apache... "
    
    # Create SSL global configuration
    cat > /etc/httpd/conf.d/ssl-global.conf << 'EOF'
# Configuración SSL Global para DaloRADIUS
LoadModule ssl_module modules/mod_ssl.so

# Configurar Session Cache para eliminar warnings
SSLSessionCache shmcb:/var/cache/mod_ssl/scache(512000)
SSLSessionCacheTimeout 300

# Configuración SSL global
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder on
EOF

    # Create directory for SSL cache
    mkdir -p /var/cache/mod_ssl >/dev/null 2>&1
    chown apache:apache /var/cache/mod_ssl >/dev/null 2>&1
    chmod 700 /var/cache/mod_ssl >/dev/null 2>&1
    
    # Set proper permissions
    chown root:root /etc/httpd/conf.d/ssl-global.conf >/dev/null 2>&1
    chmod 644 /etc/httpd/conf.d/ssl-global.conf >/dev/null 2>&1
    
    print_green "OK"
}

# Function to fix Apache module loading warnings - ACTUALIZADA
apache_fix_modules() {
    echo -n "[+] Fixing Apache module loading... "
    
    # Ensure mod_headers is loaded (avoid duplicates)
    if ! grep -q "LoadModule headers_module" /etc/httpd/conf.modules.d/00-base.conf; then
        echo "LoadModule headers_module modules/mod_headers.so" >> /etc/httpd/conf.modules.d/00-base.conf
    fi
    
    # Ensure mod_rewrite is loaded (avoid duplicates)
    if ! grep -q "LoadModule rewrite_module" /etc/httpd/conf.modules.d/00-base.conf; then
        echo "LoadModule rewrite_module modules/mod_rewrite.so" >> /etc/httpd/conf.modules.d/00-base.conf
    fi
    
    # Remove duplicate SSL module loading to avoid warnings
    # Keep only one LoadModule ssl_module directive
    if [ -f /etc/httpd/conf.d/ssl-global.conf ]; then
        # Remove any other SSL module loading
        find /etc/httpd/conf.modules.d/ -name "*.conf" -exec sed -i '/LoadModule ssl_module/d' {} \; >/dev/null 2>&1
    fi
    
    print_green "OK"
}

# Function to set up HTTP to HTTPS redirect for users
apache_setup_users_redirect() {
    echo -n "[+] Setting up HTTP to HTTPS redirect for users... "
	
	# Get server name automatically
    SERVER_NAME=$(hostname | awk '{print $1}')
    
    cat > /etc/httpd/conf.d/users-redirect.conf << EOF
<VirtualHost *:80>
    ServerName ${SERVER_NAME}
	ServerAdmin ${DALORADIUS_SERVER_ADMIN}
    DocumentRoot ${DALORADIUS_ROOT_DIRECTORY}/app/users
    
    # Redirect all HTTP traffic to HTTPS
	Redirect 301 / https://${SERVER_NAME}:443/
    
    ErrorLog /var/log/httpd/daloradius/users/redirect_error.log
    CustomLog /var/log/httpd/daloradius/users/redirect_access.log combined
</VirtualHost>
EOF
    
    print_green "OK"
}

# Function to set up HTTP to HTTPS redirect for operators
apache_setup_operators_redirect() {
    echo -n "[+] Setting up HTTP to HTTPS redirect for operators... "
    
	# Get server name automatically
    SERVER_NAME=$(hostname | awk '{print $1}')
	
    cat > /etc/httpd/conf.d/operators-redirect.conf << EOF
<VirtualHost *:8000>
	ServerName ${SERVER_NAME}
    ServerAdmin ${DALORADIUS_SERVER_ADMIN}
    DocumentRoot ${DALORADIUS_ROOT_DIRECTORY}/app/operators
    
    # Redirect all HTTP traffic to HTTPS
    Redirect 301 / https://${SERVER_NAME}:8443/
	
	ErrorLog /var/log/httpd/daloradius/operators/redirect_error.log
    CustomLog /var/log/httpd/daloradius/operators/redirect_access.log combined	
</VirtualHost>
EOF
    
    print_green "OK"
}

# Function to disable default SSL configuration that causes conflicts
apache_disable_default_ssl() {
    echo -n "[+] Disabling default SSL configuration... "
    
    # Check if default ssl.conf exists and has VirtualHost
    if [ -f /etc/httpd/conf.d/ssl.conf ]; then
        # Check if it contains a VirtualHost that conflicts
        if grep -q "VirtualHost.*:443" /etc/httpd/conf.d/ssl.conf; then
            # Backup and disable the conflicting VirtualHost
            cp /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf.backup >/dev/null 2>&1
            
            # Comment out the VirtualHost section
            sed -i '/^<VirtualHost.*:443>/,/^<\/VirtualHost>/s/^/#/' /etc/httpd/conf.d/ssl.conf >/dev/null 2>&1
            
            print_green "OK"
        else
            print_green "OK - No conflicts found"
        fi
    else
        print_green "OK - No default ssl.conf found"
    fi
}

# Function to set up Apache HTTPS site for operators
apache_setup_operators_site() {
    echo -n "[+] Setting up Apache HTTPS site for operators... "
    
    cat > /etc/httpd/conf.d/operators.conf << EOF
<VirtualHost *:${DALORADIUS_OPERATORS_PORT}>
    ServerAdmin ${DALORADIUS_SERVER_ADMIN}
    DocumentRoot ${DALORADIUS_ROOT_DIRECTORY}/app/operators
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/ssl/daloradius/daloradius.crt
    SSLCertificateKeyFile /etc/ssl/daloradius/daloradius.key
    
    # SSL Security Settings
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder on
    
    <Directory ${DALORADIUS_ROOT_DIRECTORY}/app/operators>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Additional security
    <Directory ${DALORADIUS_ROOT_DIRECTORY}/app/operators/config>
        Require all denied
    </Directory>
    
    # Deny access to sensitive directories
    <Directory ${DALORADIUS_ROOT_DIRECTORY}/app/operators/includes>
        Require all denied
    </Directory>
    
    ErrorLog /var/log/httpd/daloradius/operators/error.log
    CustomLog /var/log/httpd/daloradius/operators/access.log combined
</VirtualHost>
EOF
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to init operators site. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to set up Apache HTTPS site for users
apache_setup_users_site() {
    echo -n "[+] Setting up Apache HTTPS site for users... "
    
    cat > /etc/httpd/conf.d/users.conf << EOF
<VirtualHost *:${DALORADIUS_USERS_PORT}>
    ServerAdmin ${DALORADIUS_SERVER_ADMIN}
    DocumentRoot ${DALORADIUS_ROOT_DIRECTORY}/app/users
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/ssl/daloradius/daloradius.crt
    SSLCertificateKeyFile /etc/ssl/daloradius/daloradius.key
    
    # SSL Security Settings
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder on
    
    <Directory ${DALORADIUS_ROOT_DIRECTORY}/app/users>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    
    # Additional security
    <Directory ${DALORADIUS_ROOT_DIRECTORY}/app/users/config>
        Require all denied
    </Directory>
    
    # Deny access to sensitive directories
    <Directory ${DALORADIUS_ROOT_DIRECTORY}/app/users/includes>
        Require all denied
    </Directory>
    
    ErrorLog /var/log/httpd/daloradius/users/error.log
    CustomLog /var/log/httpd/daloradius/users/access.log combined
</VirtualHost>
EOF
    
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to init users site. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to configure Fail2ban for Apache protection
setup_fail2ban() {
    echo -n "[+] Configuring Fail2ban for Apache protection... "
    
    cat > /etc/fail2ban/jail.d/apache-daloradius.conf << 'EOF'
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/httpd/daloradius/*/error.log
maxretry = 3
bantime = 3600
findtime = 600

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/httpd/daloradius/*/access.log
maxretry = 2
bantime = 86400

[apache-noscript]
enabled = true
port = http,https
filter = apache-noscript
logpath = /var/log/httpd/daloradius/*/access.log
maxretry = 6
bantime = 86400
EOF
    
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1
    
    print_green "OK"
}

# Function to enable and restart Apache
apache_enable_restart() {
    echo -n "[+] Enabling and restarting Apache... "
    if ! systemctl enable httpd.service >/dev/null 2>&1 || ! systemctl restart httpd.service >/dev/null 2>&1; then
        print_red "KO"
        echo "[!] Failed to enable and restart Apache. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to load daloRADIUS SQL schema into MariaDB
daloradius_load_sql_schema() {
    DB_DIR="${DALORADIUS_ROOT_DIRECTORY}/contrib/db"
    
    echo -n "[+] Loading daloRADIUS SQL schema into MariaDB... "
    mariadb --defaults-extra-file="${MARIADB_CLIENT_FILENAME}" < "${DB_DIR}/fr3-mariadb-freeradius.sql" >/dev/null 2>&1 & print_spinner $!
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to load freeRADIUS SQL schema into MariaDB. Aborting." >&2
        exit 1
    fi
    
    mariadb --defaults-extra-file="${MARIADB_CLIENT_FILENAME}" < "${DB_DIR}/mariadb-daloradius.sql" >/dev/null 2>&1 & print_spinner $!
    if [ $? -ne 0 ]; then
        print_red "KO"
        echo "[!] Failed to load daloRADIUS SQL schema into MariaDB. Aborting." >&2
        exit 1
    fi
    print_green "OK"
}

# Function to apply additional security measures
apply_additional_security() {
    echo -n "[+] Applying additional security measures... "
    
    # Set proper file permissions for Apache configuration
    find /etc/httpd -type f -exec chmod 644 {} \; >/dev/null 2>&1
    find /etc/httpd -type d -exec chmod 755 {} \; >/dev/null 2>&1
    
    # Fix ownership of Apache configuration
    chown -R root:root /etc/httpd/ >/dev/null 2>&1
    
    # Secure daloRADIUS files
    if [ -d "${DALORADIUS_ROOT_DIRECTORY}" ]; then
        find ${DALORADIUS_ROOT_DIRECTORY} -type f -name "*.php" -exec chmod 644 {} \; >/dev/null 2>&1
        find ${DALORADIUS_ROOT_DIRECTORY} -type d -exec chmod 755 {} \; >/dev/null 2>&1
        chown -R apache:apache ${DALORADIUS_ROOT_DIRECTORY} >/dev/null 2>&1
    fi
    
    # Remove default Apache pages
    rm -f /var/www/html/index.html >/dev/null 2>&1
    
    # Restore SELinux contexts
    restorecon -R /etc/httpd/ >/dev/null 2>&1
    if [ -d "${DALORADIUS_ROOT_DIRECTORY}" ]; then
        restorecon -R ${DALORADIUS_ROOT_DIRECTORY} >/dev/null 2>&1
    fi
    
    print_green "OK"
}

system_finalize() {
    INIT_USERNAME="administrator"
    INIT_PASSWORD=$(generate_random_string 12)
    SQL="UPDATE operators SET password='${INIT_PASSWORD}' WHERE username='${INIT_USERNAME}'"
    
    if ! mariadb --defaults-extra-file="${MARIADB_CLIENT_FILENAME}" --execute="${SQL}" >/dev/null 2>&1; then
        INIT_PASSWORD="radius"
        print_yellow "[!] Failed to update ${INIT_USERNAME}'s default password"
    fi
    
    echo -e "[+] ${GREEN}daloRADIUS with Enhanced Security for RHEL 9.6${NC} has been installed."
    echo -e " ${BLUE}Here are some installation details:${NC}"
    echo -e " - DB hostname: ${BLUE}${DB_HOST}${NC}"
    echo -e " - DB port: ${BLUE}${DB_PORT}${NC}"
    echo -e " - DB username: ${BLUE}${DB_USER}${NC}"
    echo -e " - DB password: ${BLUE}${DB_PASS}${NC}"
    echo -e " - DB schema: ${BLUE}${DB_SCHEMA}${NC}"
    echo -e " - FreeRADIUS service: ${BLUE}radiusd${NC}"
    echo -e " - Apache service: ${BLUE}httpd${NC}"
    echo -e " - PHP version: ${BLUE}$(php -v | head -n 1 | grep -o "PHP 8\.3\.[0-9]*")${NC}"
    echo -e " - FreeRADIUS source: ${BLUE}NetworkRADIUS 3.2${NC}"
    echo -e " - SSL Certificate: ${BLUE}Self-signed for ${CERT_COMMON_NAME}${NC}"
    echo -e ""
    echo -e " ${GREEN}HTTPS Access URLs:${NC}"
    echo -e " - Users' dashboard: ${BLUE}https://your-server-ip:${DALORADIUS_USERS_PORT}${NC}"
    echo -e " - Operators' dashboard: ${BLUE}https://your-server-ip:${DALORADIUS_OPERATORS_PORT}${NC}"
    echo -e ""
    echo -e " ${GREEN}HTTP Redirects (automatically redirect to HTTPS):${NC}"
    echo -e " - Users' HTTP: ${BLUE}http://your-server-ip:80${NC} → HTTPS:${DALORADIUS_USERS_PORT}"
    echo -e " - Operators' HTTP: ${BLUE}http://your-server-ip:8000${NC} → HTTPS:${DALORADIUS_OPERATORS_PORT}"
    echo -e ""
    echo -e " To log into the ${BLUE}operators' dashboard${NC}, use the following credentials:"
    echo -e " - Username: ${BLUE}${INIT_USERNAME}${NC}"
    echo -e " - Password: ${BLUE}${INIT_PASSWORD}${NC}"
    echo -e ""
    echo -e " ${YELLOW}Security Features Applied:${NC}"
    echo -e " - HTTPS with TLS 1.2+ only"
    echo -e " - Apache security hardening (CIS-based)"
    echo -e " - Fail2ban intrusion prevention"
    echo -e " - Firewall configuration"
    echo -e " - SELinux configuration"
    echo -e " - Secure file permissions"
    echo -e " - Security headers enabled"
    echo -e " - FreeRADIUS 3.2 with SQL backend"
    echo -e " - Log access permissions configured"
}

# Main function calling other functions in the correct order
main() {
    system_ensure_root
    system_update
    mariadb_install
    mariadb_secure
    mariadb_db_init
    mariadb_init_conf
    freeradius_install
    freeradius_setup_sql_mod
    freeradius_import_schema
    freeradius_enable_restart
    daloradius_install_dep
	configure_selinux_for_daloradius
    daloradius_installation
    daloradius_setup_required_dirs
    daloradius_setup_required_files
    daloradius_setup_log_permissions
    daloradius_load_sql_schema
	generate_default_ssl_certificates
    generate_ssl_certificates
    apache_disable_all_sites
    apache_security_hardening
	apache_fix_modules
	apache_configure_ssl
	apache_disable_default_ssl
    apache_setup_ports
    apache_setup_users_redirect
    apache_setup_operators_redirect
    apache_setup_operators_site
    apache_setup_users_site
    configure_firewall
    configure_selinux
    setup_fail2ban
    apply_additional_security
    apache_enable_restart
    system_finalize
    mariadb_clean_conf
	verify_selinux_config
}

# Parsing command line options
while getopts ":u:p:h:P:s:c" opt; do
    case $opt in
        u) DB_USER="$OPTARG" ;;
        p) DB_PASS="$OPTARG" ;;
        h) DB_HOST="$OPTARG" ;;
        P) DB_PORT="$OPTARG" ;;
        s) DB_SCHEMA="$OPTARG" ;;
        c) ENABLE_COLORS=false ;;
        \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
    esac
done

# Generate a random username if not provided
if [ -z "$DB_USER" ]; then
    prefix="user_"
    random_string=$(generate_random_string 6)
    DB_USER="${prefix}${random_string}"
fi

# Generate a random password if not provided
if [ -z "$DB_PASS" ]; then
    DB_PASS=$(generate_random_string 12)
fi

# Generate a random scheme if not provided
if [ -z "$DB_SCHEMA" ]; then
    prefix="radius_"
    random_string=$(generate_random_string 6)
    DB_SCHEMA="${prefix}${random_string}"
fi

# Define color codes
if $ENABLE_COLORS; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    GREEN=''
    RED=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Call the main function to start the installation process
main
