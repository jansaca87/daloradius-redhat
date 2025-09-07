# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), 
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-09-06
### Added
- **Installer (`install_daloradius_2025_V1_PHP83_RH9.sh`)**
  - Automated daloRADIUS installation on **RHEL 9.6**.
  - **FreeRADIUS 3.2** (NetworkRADIUS), **MariaDB**, **Apache + PHP 8.3** (Remi).
  - HTTPS sites for **users (443)** and **operators (8443)**, with HTTP redirects (80 → 443, 8000 → 8443).
  - Self-signed **SSL** certificate generation and localhost fallback.
  - **Firewall** rules (80, 8000, 443, 8443, 1812/udp, 1813/udp).
  - **SELinux** booleans, port mappings, contexts and a custom policy for daloRADIUS.
  - **Fail2ban** jails for Apache.
  - CIS-style **Apache hardening** (headers, methods, timeouts, request limits, ServerTokens/Signature).
  - FreeRADIUS **SQL module** setup and **schema import** for daloRADIUS.
  - Secure ownership and permissions on files and logs.
  - Random, secure defaults for DB user/password/schema if not provided.
- **Audit/Fix (`daloradius_rhel9_audit_fix.sh`)**
  - Audit of Debian/Ubuntu paths/services and conversion to RHEL 9 equivalents (Apache/FreeRADIUS/MariaDB/SSL).
  - Optional auto-fix with backups, logs and detailed **audit/final reports** under `/tmp`.
  - Specific fixes for `radius_server_info.php` and main config paths.
  - Permission corrections and enabling required PHP functions.

### Security
- Public-safe defaults and **sanitized placeholders** for certificate fields and admin email in the installer.
- No hardcoded secrets; credentials are generated at runtime when omitted.

### Documentation
- Bilingual **README (ES/EN)** and a minimal **.gitignore** for script projects.

