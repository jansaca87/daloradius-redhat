# daloRADIUS on RHEL 9 – Install & Audit (Public)

> **⚠️ IMPORTANTE / IMPORTANT**  
> **ES:** Tras ejecutar el instalador, **debes** correr el script **de auditoría y corrección** para adaptar por completo la instalación a la arquitectura de **RHEL 9** (rutas, servicios, SELinux, permisos).  
> **EN:** After running the installer, you **must** run the **audit & fix** script to fully adapt the deployment to **RHEL 9** architecture (paths, services, SELinux, permissions).
This repository contains two Bash scripts to **install** and **audit/fix** daloRADIUS on **RHEL 9.x** with opinionated security hardening.

---

## 🇪🇸 Descripción (ES)

### `install_daloradius_2025_V1_PHP83_RH9.sh`
Instalador automatizado de daloRADIUS en **RHEL 9.6** con seguridad reforzada:
- FreeRADIUS **3.2** (NetworkRADIUS), MariaDB.
- Apache + **PHP 8.3** (Remi), módulos necesarios.
- HTTPS con certificados autofirmados, **firewall**, **Fail2ban**, **SELinux** y hardening basado en CIS.
- Crea credenciales iniciales seguras y habilita paneles **HTTPS** para **usuarios** y **operadores**.

**Uso rápido (2 pasos obligatorios):**
```bash
# 1) Instalar
sudo bash install_daloradius_2025_V1_PHP83_RH9.sh -u <db_user> -p <db_pass> -s <db_schema>

# 2) Auditar y corregir (obligatorio tras instalar)
sudo bash daloradius_rhel9_audit_fix.sh
```
> Recomendado: reiniciar/validar servicios después del fix.
> `systemctl status httpd radiusd mariadb`

### `daloradius_rhel9_audit_fix.sh`
Auditoría y corrección para instalaciones existentes de daloRADIUS en RHEL 9.
- Detecta rutas/servicios Debian/Ubuntu y los corrige a equivalentes de RHEL (Apache/FreeRADIUS/MariaDB/SSL).
- Ajusta permisos, habilita funciones PHP requeridas y corrige archivos conocidos.
- Genera **reporte de auditoría** y **reporte final** en `/tmp`.

**Uso:**
```bash
sudo bash daloradius_rhel9_audit_fix.sh
```

---

## 🇬🇧 Description (EN)

### `install_daloradius_2025_V1_PHP83_RH9.sh`
Automated **daloRADIUS** installer for **RHEL 9.6** with enhanced security:
- FreeRADIUS **3.2** (NetworkRADIUS), MariaDB.
- Apache + **PHP 8.3** (Remi) and required extensions.
- Self‑signed HTTPS, **firewall**, **Fail2ban**, **SELinux**, and CIS‑style hardening.
- Generates secure initial credentials and exposes **HTTPS** dashboards for **users** and **operators**.

**Quick start (2 mandatory steps):**
```bash
# 1) Install
sudo bash install_daloradius_2025_V1_PHP83_RH9.sh -u <db_user> -p <db_pass> -s <db_schema>

# 2) Audit & fix (mandatory after install)
sudo bash daloradius_rhel9_audit_fix.sh
```
> Recommended: restart/verify services after the fix.
> `systemctl status httpd radiusd mariadb`

### `daloradius_rhel9_audit_fix.sh`
Audit & fix tool for existing daloRADIUS deployments on RHEL 9.
- Finds Debian/Ubuntu‑style paths/services and converts them to RHEL equivalents.
- Fixes permissions, enables needed PHP functions, and patches known files.
- Produces **audit** and **final** reports under `/tmp`.

**Run:**
```bash
sudo bash daloradius_rhel9_audit_fix.sh
```

**¿Por qué es obligatorio? / Why is this required?**  
- **ES:** El código upstream de daloRADIUS y múltiples guías asumen rutas/servicios estilo Debian/Ubuntu. El script `daloradius_rhel9_audit_fix.sh` las **convierte** a los equivalentes de **RHEL 9** (Apache/httpd, FreeRADIUS/radiusd, MariaDB, `/etc/raddb`, `/var/log/radius`, SELinux contexts, permisos, etc.).  
- **EN:** Upstream code and guides often assume Debian/Ubuntu-style paths/services. The `daloradius_rhel9_audit_fix.sh` script **converts** them to **RHEL 9** equivalents (Apache/httpd, FreeRADIUS/radiusd, MariaDB, `/etc/raddb`, `/var/log/radius`, SELinux contexts, permissions, etc.).

---

## Notes
- These scripts are intended for lab/PoC or controlled environments. Review before using in production.
- Update SSL placeholders in the installer if you plan to use real certificates:
  ```bash
  CERT_COMMON_NAME="radius.example.com"
  CERT_EMAIL="admin@example.com"
  # ...and related fields
  ```

## License
MIT