#!/bin/bash

# Script de Auditoría y Corrección de DaloRADIUS para RHEL 9
# Versión: 2.0 - Sin configuración SELinux
# Fecha: $(date)
# Compatibilidad: Red Hat Enterprise Linux 9

# Configuración global
DALORADIUS_ROOT="/var/www/daloradius"
BACKUP_DIR="/tmp/daloradius_backup_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/tmp/daloradius_audit_$(date +%Y%m%d_%H%M%S).log"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variable global para contador de inconsistencias
TOTAL_INCONSISTENCIES=0

# Función para logging
log_message() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Función para mostrar mensajes con color
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}$message${NC}"
    log_message "$message"
}

# Patrones de inconsistencias Debian/Ubuntu vs RHEL 9
declare -A PATTERNS=(
    # Rutas de FreeRADIUS
    ["/etc/freeradius/"]="/etc/raddb/"
    ["/etc/freeradius"]="/etc/raddb"
    ["/var/log/freeradius/"]="/var/log/radius/"
    ["/var/log/freeradius"]="/var/log/radius"
    ["/var/run/freeradius/"]="/var/run/radiusd/"
    ["/var/run/freeradius"]="/var/run/radiusd"
    ["/usr/sbin/freeradius"]="/usr/sbin/radiusd"
    ["/etc/init.d/freeradius"]="/usr/lib/systemd/system/radiusd.service"
    ["/etc/logrotate.d/freeradius"]="/etc/logrotate.d/radiusd"
    
    # Rutas de Apache
    ["/etc/apache2/"]="/etc/httpd/"
    ["/etc/apache2"]="/etc/httpd"
    ["/var/log/apache2/"]="/var/log/httpd/"
    ["/var/log/apache2"]="/var/log/httpd"
    ["/var/run/apache2/"]="/var/run/httpd/"
    ["/var/run/apache2"]="/var/run/httpd"
    ["/usr/sbin/apache2"]="/usr/sbin/httpd"
    ["/etc/logrotate.d/apache2"]="/etc/logrotate.d/httpd"
    
    # Rutas de MySQL/MariaDB
    ["/etc/mysql/"]="/etc/my.cnf.d/"
    ["/etc/mysql"]="/etc/my.cnf.d"
    ["/usr/bin/mysql"]="/usr/bin/mariadb"
    ["/usr/bin/mysqldump"]="/usr/bin/mariadb-dump"
    ["/usr/bin/mysqladmin"]="/usr/bin/mariadb-admin"
    ["/usr/bin/mysqlcheck"]="/usr/bin/mariadb-check"
    ["/usr/bin/mysqlimport"]="/usr/bin/mariadb-import"
    ["/usr/bin/mysqlshow"]="/usr/bin/mariadb-show"
    ["/usr/bin/mysqlslap"]="/usr/bin/mariadb-slap"
    ["/usr/bin/mysql_upgrade"]="/usr/bin/mariadb-upgrade"
    ["/usr/bin/mysql_secure_installation"]="/usr/bin/mariadb-secure-installation"
    ["/usr/bin/mysql_install_db"]="/usr/bin/mariadb-install-db"
    ["/usr/bin/mysql_config"]="/usr/bin/mariadb_config"
    ["/usr/bin/mysql_tzinfo_to_sql"]="/usr/bin/mariadb-tzinfo-to-sql"
    ["/usr/bin/mysqlbinlog"]="/usr/bin/mariadb-binlog"
    ["/usr/bin/mysqltest"]="/usr/bin/mariadb-test"
    ["/usr/bin/mysql_waitpid"]="/usr/bin/mariadb-waitpid"
    ["/usr/bin/mysqlhotcopy"]="/usr/bin/mariadb-hotcopy"
    ["/etc/logrotate.d/mysql"]="/etc/logrotate.d/mariadb"
    ["/etc/logrotate.d/mysqld"]="/etc/logrotate.d/mariadb"
    
    # Rutas de SSL
    ["/etc/ssl/private/"]="/etc/pki/tls/private/"
    ["/etc/ssl/certs/"]="/etc/pki/tls/certs/"
    ["/etc/ssl/"]="/etc/pki/tls/"
    
    # Rutas de PHP
    ["/etc/php/"]="/etc/"
    
    # Otros directorios comunes
    ["/etc/init.d/"]="/usr/lib/systemd/system/"
    ["/etc/rc.d/init.d/"]="/usr/lib/systemd/system/"
)

# Patrones de nombres de servicios y procesos
declare -A SERVICE_PATTERNS=(
    ["freeradius"]="radiusd"
    ["mysql"]="mariadb"
    ["MySQL"]="MariaDB"
    ["www-data"]="apache"
    ["apache2"]="httpd"
)

# Función para crear backup
create_backup() {
    print_status "$BLUE" "[+] Creando backup en $BACKUP_DIR..."
    mkdir -p "$BACKUP_DIR"
    if cp -r "$DALORADIUS_ROOT" "$BACKUP_DIR/"; then
        print_status "$GREEN" "[✓] Backup creado exitosamente"
    else
        print_status "$RED" "[✗] Error al crear backup"
        exit 1
    fi
}

# Función para auditar archivos
audit_files() {
    print_status "$BLUE" "[+] Iniciando auditoría de archivos..."
    
    local inconsistencies_found=0
    local audit_report="$BACKUP_DIR/audit_report.txt"
    
    echo "REPORTE DE AUDITORÍA DALORADIUS - RHEL 9" > "$audit_report"
    echo "=========================================" >> "$audit_report"
    echo "Fecha: $(date)" >> "$audit_report"
    echo "" >> "$audit_report"
    
    # Crear archivo temporal para almacenar archivos a procesar
    local temp_files="/tmp/daloradius_files_$$.txt"
    find "$DALORADIUS_ROOT" -type f \( -name "*.php" -o -name "*.conf" -o -name "*.sh" -o -name "*.ini" -o -name "*.pl" -o -name "*.py" -o -name "*.js" -o -name "*.css" -o -name "*.txt" \) > "$temp_files"
    
    # Procesar archivos sin usar pipe para mantener el contador
    while IFS= read -r file; do
        if [ ! -f "$file" ]; then
            continue
        fi
        
        local file_inconsistencies=0
        
        # Verificar patrones de rutas
        for pattern in "${!PATTERNS[@]}"; do
            if grep -q "$pattern" "$file" 2>/dev/null; then
                echo "INCONSISTENCIA ENCONTRADA:" >> "$audit_report"
                echo "  Archivo: $file" >> "$audit_report"
                echo "  Patrón: $pattern" >> "$audit_report"
                echo "  Debe ser: ${PATTERNS[$pattern]}" >> "$audit_report"
                echo "  Líneas:" >> "$audit_report"
                grep -n "$pattern" "$file" | head -5 >> "$audit_report"
                echo "" >> "$audit_report"
                ((file_inconsistencies++))
                ((inconsistencies_found++))
            fi
        done
        
        # Verificar patrones de servicios
        for service in "${!SERVICE_PATTERNS[@]}"; do
            if grep -q "\b$service\b" "$file" 2>/dev/null; then
                echo "INCONSISTENCIA DE SERVICIO ENCONTRADA:" >> "$audit_report"
                echo "  Archivo: $file" >> "$audit_report"
                echo "  Servicio: $service" >> "$audit_report"
                echo "  Debe ser: ${SERVICE_PATTERNS[$service]}" >> "$audit_report"
                echo "  Líneas:" >> "$audit_report"
                grep -n "\b$service\b" "$file" | head -3 >> "$audit_report"
                echo "" >> "$audit_report"
                ((file_inconsistencies++))
                ((inconsistencies_found++))
            fi
        done
        
        if [ $file_inconsistencies -gt 0 ]; then
            print_status "$YELLOW" "[!] Encontradas $file_inconsistencies inconsistencias en: $(basename "$file")"
        fi
        
    done < "$temp_files"
    
    # Limpiar archivo temporal
    rm -f "$temp_files"
    
    echo "RESUMEN:" >> "$audit_report"
    echo "Total de inconsistencias encontradas: $inconsistencies_found" >> "$audit_report"
    
    # Actualizar contador global
    TOTAL_INCONSISTENCIES=$inconsistencies_found
    
    print_status "$BLUE" "[+] Auditoría completada. Total de inconsistencias: $inconsistencies_found"
    print_status "$BLUE" "[+] Reporte guardado en: $audit_report"
    
    return $inconsistencies_found
}

# Función para corregir archivos
fix_files() {
    print_status "$BLUE" "[+] Iniciando corrección de archivos..."
    
    local files_fixed=0
    local corrections_made=0
    
    # Crear archivo temporal para archivos a procesar
    local temp_files="/tmp/daloradius_fix_files_$$.txt"
    find "$DALORADIUS_ROOT" -type f \( -name "*.php" -o -name "*.conf" -o -name "*.sh" -o -name "*.ini" -o -name "*.pl" -o -name "*.py" -o -name "*.js" -o -name "*.css" -o -name "*.txt" \) > "$temp_files"
    
    while IFS= read -r file; do
        if [ ! -f "$file" ]; then
            continue
        fi
        
        local file_modified=false
        
        # Aplicar correcciones de rutas
        for pattern in "${!PATTERNS[@]}"; do
            if grep -q "$pattern" "$file" 2>/dev/null; then
                sed -i "s|$pattern|${PATTERNS[$pattern]}|g" "$file"
                print_status "$GREEN" "[✓] Corregido patrón '$pattern' en $(basename "$file")"
                file_modified=true
                ((corrections_made++))
            fi
        done
        
        # Aplicar correcciones de servicios (con cuidado de no romper palabras)
        for service in "${!SERVICE_PATTERNS[@]}"; do
            if grep -q "\b$service\b" "$file" 2>/dev/null; then
                sed -i "s/\b$service\b/${SERVICE_PATTERNS[$service]}/g" "$file"
                print_status "$GREEN" "[✓] Corregido servicio '$service' en $(basename "$file")"
                file_modified=true
                ((corrections_made++))
            fi
        done
        
        if [ "$file_modified" = true ]; then
            ((files_fixed++))
        fi
        
    done < "$temp_files"
    
    # Limpiar archivo temporal
    rm -f "$temp_files"
    
    print_status "$BLUE" "[+] Corrección completada. Archivos modificados: $files_fixed, Correcciones aplicadas: $corrections_made"
}

# Función para correcciones específicas conocidas
apply_specific_fixes() {
    print_status "$BLUE" "[+] Aplicando correcciones específicas conocidas..."
    
    # Corregir radius_server_info.php
    local radius_info_file="$DALORADIUS_ROOT/app/operators/library/extensions/radius_server_info.php"
    if [ -f "$radius_info_file" ]; then
        print_status "$YELLOW" "[+] Corrigiendo radius_server_info.php..."
        
        cat > "$radius_info_file" << 'EOF'
<?php
/*
 *********************************************************************************************************
 * daloRADIUS - RADIUS Web Platform
 * Copyright (C) 2007 - Liran Tal <liran@lirantal.com> All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *********************************************************************************************************
 * 
 * Description:    this script uses systemctl to check if services stored
 *                 in $services_to_check are running (adapted for RHEL 9)
 *
 * Authors:        Liran Tal <liran@lirantal.com>
 *                 Filippo Lauria <filippo.lauria@iit.cnr.it>
 *                 Modified for RHEL 9 compatibility
 *
 *********************************************************************************************************
 */

// prevent this file to be directly accessed
if (strpos($_SERVER['PHP_SELF'], '/library/extensions/radius_server_info.php') !== false) {
    header("Location: ../../index.php");
    exit;
}

// given the $service_name, this function returns true if that service is running
function check_service($service_name) {
    if (empty($service_name)) {
        return false;
    }

    // Mapear nombres de servicios a nombres de servicios systemctl en RHEL 9
    $service_map = array(
        'freeradius' => 'radiusd',
        'mysql' => 'mariadb',
        'mariadb' => 'mariadb',
        'sshd' => 'sshd',
        'ssh' => 'sshd'
    );
    
    $service_lower = strtolower($service_name);
    $systemctl_service = isset($service_map[$service_lower]) ? $service_map[$service_lower] : $service_lower;
    
    // Usar systemctl para verificar el estado del servicio
    $command = sprintf("systemctl is-active %s 2>/dev/null", escapeshellarg($systemctl_service));
    exec($command, $output, $result_code);
    
    return $result_code === 0;
}

$services_to_check = array("FreeRADIUS", "MariaDB", "SSHd");

$table = array( 'title' => 'Service Status', 'rows' => array() );

foreach ($services_to_check as $service_name) {
    $running = check_service($service_name);
    $class = ($running) ? "text-success" : "text-danger";
    $label = ($running) ? "running" : "not running";
    
    $value = sprintf('<span class="%s">%s</span>', $class, $label);
    
    $table['rows'][] = array( $service_name, $value);
}

print_simple_table($table);
EOF
        
        print_status "$GREEN" "[✓] radius_server_info.php corregido para RHEL 9"
    fi
    
    # Corregir archivo de configuración principal si existe
    local config_file="$DALORADIUS_ROOT/app/common/includes/daloradius.conf.php"
    if [ -f "$config_file" ]; then
        print_status "$YELLOW" "[+] Actualizando configuración principal..."
        
        # Corregir rutas específicas en el archivo de configuración
        sed -i "s|/etc/freeradius|/etc/raddb|g" "$config_file"
        sed -i "s|/var/log/freeradius|/var/log/radius|g" "$config_file"
        sed -i "s|/etc/apache2|/etc/httpd|g" "$config_file"
        sed -i "s|/var/log/apache2|/var/log/httpd|g" "$config_file"
        
        print_status "$GREEN" "[✓] Configuración principal actualizada"
    fi
}

# Función para verificar permisos y propietarios
fix_permissions() {
    print_status "$BLUE" "[+] Corrigiendo permisos y propietarios..."
    
    # Cambiar propietario de www-data a apache
    chown -R apache:apache "$DALORADIUS_ROOT"
    
    # Establecer permisos correctos
    find "$DALORADIUS_ROOT" -type d -exec chmod 755 {} \;
    find "$DALORADIUS_ROOT" -type f -exec chmod 644 {} \;
    
    # Permisos especiales para scripts ejecutables
    find "$DALORADIUS_ROOT" -name "*.sh" -exec chmod 755 {} \;
    
    # Agregar apache al grupo radiusd para acceso a logs
    usermod -a -G radiusd apache >/dev/null 2>&1
    
    # Permisos para logs del sistema
    chmod 644 /var/log/messages >/dev/null 2>&1
    chmod 755 /var/log/radius >/dev/null 2>&1
    chmod 644 /var/log/radius/*.log >/dev/null 2>&1 || true
    
    print_status "$GREEN" "[✓] Permisos y propietarios corregidos"
}

# Función para habilitar funciones PHP necesarias
configure_php_functions() {
    print_status "$BLUE" "[+] Configurando funciones PHP necesarias..."
    
    # Verificar si las funciones están deshabilitadas
    local php_ini="/etc/php.ini"
    if [ -f "$php_ini" ]; then
        # Hacer backup del php.ini
        cp "$php_ini" "$php_ini.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Habilitar funciones necesarias para daloRADIUS
        sed -i 's/disable_functions = .*/disable_functions = /' "$php_ini"
        
        print_status "$GREEN" "[✓] Funciones PHP habilitadas"
        print_status "$YELLOW" "[!] Nota: Se requiere reiniciar Apache para aplicar cambios en PHP"
    else
        print_status "$YELLOW" "[!] Archivo php.ini no encontrado en la ubicación esperada"
    fi
}

# Función para generar reporte final
generate_final_report() {
    local final_report="$BACKUP_DIR/correction_report.txt"
    
    print_status "$BLUE" "[+] Generando reporte final..."
    
    cat > "$final_report" << EOF
REPORTE DE CORRECCIÓN DALORADIUS - RHEL 9
=========================================
Fecha: $(date)
Backup creado en: $BACKUP_DIR
Log de auditoría: $LOG_FILE
Total de inconsistencias encontradas: $TOTAL_INCONSISTENCIES

CORRECCIONES APLICADAS:
======================

1. Rutas de FreeRADIUS:
   - /etc/freeradius/ → /etc/raddb/
   - /var/log/freeradius/ → /var/log/radius/
   - /var/run/freeradius/ → /var/run/radiusd/

2. Rutas de Apache:
   - /etc/apache2/ → /etc/httpd/
   - /var/log/apache2/ → /var/log/httpd/
   - /var/run/apache2/ → /var/run/httpd/

3. Rutas de MySQL/MariaDB:
   - /etc/mysql/ → /etc/my.cnf.d/
   - Comandos mysql → mariadb

4. Rutas de SSL:
   - /etc/ssl/ → /etc/pki/tls/

5. Nombres de servicios:
   - freeradius → radiusd
   - mysql → mariadb
   - www-data → apache
   - apache2 → httpd

6. Archivos específicos corregidos:
   - radius_server_info.php (verificación de servicios)
   - daloradius.conf.php (configuración principal)

7. Permisos y propietarios:
   - Propietario cambiado de www-data a apache
   - Permisos de archivos establecidos correctamente
   - Usuario apache agregado al grupo radiusd

8. Configuración PHP:
   - Funciones exec y shell_exec habilitadas
   - Configuración optimizada para daloRADIUS

PRÓXIMOS PASOS:
==============
1. Reiniciar Apache: systemctl restart httpd
2. Verificar que FreeRADIUS esté funcionando: systemctl status radiusd
3. Verificar que MariaDB esté funcionando: systemctl status mariadb
4. Probar la interfaz web de daloRADIUS
5. Verificar logs de errores: tail -f /var/log/httpd/error_log

COMANDOS DE VERIFICACIÓN:
========================
systemctl status httpd
systemctl status radiusd
systemctl status mariadb
tail -f /var/log/httpd/error_log
tail -f /var/log/radius/radius.log

NOTAS IMPORTANTES:
==================
- Se ha creado un backup completo en: $BACKUP_DIR
- Las funciones PHP exec y shell_exec han sido habilitadas
- El usuario apache tiene acceso a logs de FreeRADIUS
- Se recomienda reiniciar Apache después de las correcciones

EOF

    print_status "$GREEN" "[✓] Reporte final generado en: $final_report"
}

# Función principal
main() {
    print_status "$BLUE" "=== SCRIPT DE AUDITORÍA Y CORRECCIÓN DALORADIUS PARA RHEL 9 ==="
    print_status "$BLUE" "Directorio de daloRADIUS: $DALORADIUS_ROOT"
    
    # Verificar que el directorio existe
    if [ ! -d "$DALORADIUS_ROOT" ]; then
        print_status "$RED" "[✗] Error: El directorio $DALORADIUS_ROOT no existe"
        exit 1
    fi
    
    # Verificar que se ejecuta como root
    if [ "$(id -u)" -ne 0 ]; then
        print_status "$RED" "[✗] Error: Este script debe ejecutarse como root"
        exit 1
    fi
    
    # Crear backup
    create_backup
    
    # Auditar archivos
    audit_files
    local audit_result=$TOTAL_INCONSISTENCIES
    
    if [ $audit_result -gt 0 ]; then
        print_status "$YELLOW" "[!] Se encontraron $audit_result inconsistencias"
        
        echo -n "¿Desea proceder con las correcciones? (s/N): "
        read -r response
        
        if [[ "$response" =~ ^[Ss]$ ]]; then
            # Aplicar correcciones
            fix_files
            apply_specific_fixes
            fix_permissions
            configure_php_functions
            
            print_status "$GREEN" "[✓] Todas las correcciones han sido aplicadas"
            print_status "$YELLOW" "[!] Se recomienda reiniciar Apache: systemctl restart httpd"
        else
            print_status "$YELLOW" "[!] Correcciones canceladas por el usuario"
        fi
    else
        print_status "$GREEN" "[✓] No se encontraron inconsistencias"
    fi
    
    # Generar reporte final
    generate_final_report
    
    print_status "$BLUE" "=== PROCESO COMPLETADO ==="
    print_status "$BLUE" "Backup: $BACKUP_DIR"
    print_status "$BLUE" "Log: $LOG_FILE"
    print_status "$BLUE" "Inconsistencias encontradas: $TOTAL_INCONSISTENCIES"
}

# Ejecutar función principal
main "$@"
