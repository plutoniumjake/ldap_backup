# sfi-ldap-backup-restore.sh

A safe-ish backup and restore helper for the sfi-ldap (389 Directory Server) service.

This script:
- Creates a dsctl db2bak backup, packages it with /etc/dirsrv into a tarball,
- Encrypts the tarball with OpenSSL (AES-128-CBC using a passphrase file),
- Writes Prometheus textfile metrics (node_exporter textfile collector),
- Keeps the 7 most recent encrypted backups (rotates older ones),
- Provides a restore routine that will decrypt, extract and attempt to restore:
  - Prefer using `dsctl sfi-ldap db2restore` if available,
  - Otherwise performs a best-effort file restore of /etc/dirsrv and the DS DB directory.

Important: ALWAYS test the restore on a non-production host/replica first.

Status: single-file Bash script: sfi-ldap-backup-restore.sh

---

Table of contents
- Overview
- Requirements / Prerequisites
- Environment variables / Configuration
- Installation
- Usage
- Restore behavior and limitations
- Prometheus metrics
- Security and permissions
- Troubleshooting
- Notes / Suggested improvements
- License

---

Overview
--------
The script automates regular backups of the 389 Directory Server for the host, encrypts them, and keeps a small retention of recent backups. It writes metrics for Prometheus node_exporter (textfile collector) so you can monitor backup age/size/count.

Requirements / Prerequisites
---------------------------
- Linux systemd host running dirsrv@sfi-ldap.service (adjust service name in-script if different).
- dsctl installed and available at /usr/sbin/dsctl (used for db2bak and optionally db2restore).
- openssl (for encrypt/decrypt).
- tar, find, stat, du, awk, sort, mapfile — standard GNU userland utilities.
- node_exporter (optional) textfile collector path defaults to /var/lib/node_exporter.
- The script must be run with sufficient privileges to stop/start dirsrv and manipulate DB/config files (typically root).
- Ensure /nfs/dumps (or whatever mount BACKUP_DIR points to) is mounted and writable by the invoking user.

Environment variables / Configuration
-------------------------------------
The following variables are defined near the top of the script and can be overridden via environment or edited in the script:

- BACKUP_DIR (default: /nfs/dumps/$(hostname -s))
  - Where encrypted backups are stored.
- AES_PASSWORD_FILE (default: /root/backup_tools/aes-128.pass)
  - File containing the passphrase used by OpenSSL for encryption/decryption.
  - Should be readable only by the backup runner (recommend chmod 600).
- TEXTFILE_COLLECTOR_DIR (default: /var/lib/node_exporter)
  - Directory for node_exporter textfile collector metrics.
- DS_DB_PATH (default: /var/lib/dirsrv/slapd-sfi-ldap)
  - Path to the local 389-dirsrv database directory used by best-effort restore fallback.
  - Can be overridden by exporting DS_DB_PATH prior to running the script.
- LOGFILE (default: /var/log/sfi-ldap-backup-restore.sh.log)
  - Location of the script log.
- TMPDIR (internal) - a temporary work area is created per run.

Ownership behavior
------------------
The script will create BACKUP_DIR if missing. It will chown BACKUP_DIR to the user who invoked the script:
- If run under sudo, it prefers SUDO_USER (the original user).
- Otherwise it falls back to the current user (id -un).
This avoids hard-coding root ownership. If the detected user doesn't exist or the script doesn't have permission to chown, a warning is logged and ownership is left unchanged.

Installation
------------
1. Place the script on a host with the services and tools noted above:
   - e.g. /usr/local/sbin/sfi-ldap-backup-restore.sh
2. Ensure it is executable:
   - chmod 750 /usr/local/sbin/sfi-ldap-backup-restore.sh
3. Ensure AES_PASSWORD_FILE exists and is permissioned (600) and readable by the runner:
   - mkdir -p /root/backup_tools
   - echo "your-passphrase" > /root/backup_tools/aes-128.pass
   - chmod 600 /root/backup_tools/aes-128.pass
4. Ensure /nfs/dumps is mounted and writable by the invoking user or adjust BACKUP_DIR.

Usage
-----
Basic commands:

- Create a backup (run as root or with sudo):
  - sudo /usr/local/sbin/sfi-ldap-backup-restore.sh -b

- Restore the latest backup:
  - sudo /usr/local/sbin/sfi-ldap-backup-restore.sh -r

- Restore a specific backup file:
  - sudo /usr/local/sbin/sfi-ldap-backup-restore.sh -r /nfs/dumps/hostname/hostname_backup.2025-09-22.tar.gz.enc

- Show help:
  - /usr/local/sbin/sfi-ldap-backup-restore.sh -h

Environment overrides (examples):
- Use a different AES password file:
  - AES_PASSWORD_FILE=/path/to/pass sudo /usr/local/sbin/sfi-ldap-backup-restore.sh -b
- Use a different DS DB path for restores:
  - DS_DB_PATH=/custom/dirsrv/db sudo /usr/local/sbin/sfi-ldap-backup-restore.sh -r

Restore behavior and limitations
-------------------------------
1. The script will attempt to decrypt the .tar.gz.enc backup using AES_PASSWORD_FILE and extract to a temporary directory.
2. If `dsctl` is available, the script will attempt:
   - /usr/sbin/dsctl sfi-ldap db2restore <extracted-backup-dir>
   - This is the preferred path — verify the DS version and dsctl subcommands on your platform.
3. If dsctl restore fails or is not available, the script will attempt a best-effort file restore:
   - Restore /etc/dirsrv from the archive (the script moves existing /etc/dirsrv to a backup location).
   - Copy extracted DB files into DS_DB_PATH (backing up any existing DS_DB_PATH to a temporary location).
   - NOTE: This file-based restore is best-effort and may not be sufficient for your DS version — testing is required.
4. After restore, the script attempts to start dirsrv@sfi-ldap.service.
5. ALWAYS test restores on a non-production replica or VM to confirm exact behavior for your environment.

Prometheus metrics (node_exporter textfile collector)
----------------------------------------------------
The script writes a file named node_file_database_dump.prom in TEXTFILE_COLLECTOR_DIR with the following metrics:
- node_file_database_dump_count{database="<hostname>"} <count>
- node_file_database_dump_total_size_bytes{database="<hostname>"} <total bytes>
- node_file_database_dump_latest_mtime{database="<hostname>"} <epoch seconds>
- node_file_database_dump_latest_size_bytes{database="<hostname>"} <bytes>

The file is written atomically to avoid partial reads.

Rotation / retention
--------------------
The script keeps the 7 most recent encrypted backups and deletes older ones. If you want a different retention count, edit the rotate_old_backups function (the current code uses head -n -7) or modify to accept an environment variable RUNTIME_RETAIN_COUNT and adapt the code.

Security and permissions
------------------------
- AES_PASSWORD_FILE should be permissioned to only the user running the script:
  - chmod 600 /root/backup_tools/aes-128.pass
- The script must be run by a user that can stop/start dirsrv and access DB/config directories (usually root).
- Be mindful of where you store the backups: /nfs/dumps is a suggested location but ensure it is secure and has appropriate access controls.
- The script logs to /var/log/sfi-ldap-backup-restore.sh.log — ensure that log file is also protected if it may contain sensitive paths/messages.

Troubleshooting
---------------
- "db2bak failed": check dsctl output, verify dsctl version and permissions.
- "Encryption failed": ensure AES_PASSWORD_FILE exists and the passphrase is correct.
- "Decryption failed": verify AES_PASSWORD_FILE matches the passphrase used for encryption and file integrity.
- Ownership warnings when creating BACKUP_DIR: if script cannot chown the directory, either run as a user that can chown or adjust permissions manually.
- Prometheus metrics missing: ensure TEXTFILE_COLLECTOR_DIR is the directory used by node_exporter and that the file has the expected name and is readable.

Recommended testing checklist (before using in production)
----------------------------------------------------------
- Run a manual backup on a non-production host:
  - Confirm a .tar.gz.enc file appears in BACKUP_DIR.
  - Confirm Prometheus metric file updates.
- Run a restore on a test replica:
  - Use a local copy of the .tar.gz.enc and run the script -r against it.
  - Verify the extracted layout and whether dsctl db2restore succeeds.
  - If dsctl restore isn't supported, confirm the best-effort restore gets services back to a usable state.
- Test rotation by creating more than 7 backups and ensure older files are deleted.

Possible improvements
---------------------
- Make retention count configurable via environment variable.
- Add more robust dsctl restore logic tailored to the exact dsctl version.
- Add a systemd timer or cron unit with example unit file for scheduled backups.
- Add unit tests or a dry-run mode that only simulates actions.
- Add email/alerting on backup failures.

Example systemd timer (suggestion)
----------------------------------
You can run the script via a systemd service and timer. Example (not included in the script):
- /etc/systemd/system/sfi-ldap-backup.service
- /etc/systemd/system/sfi-ldap-backup.timer

(Provide unit files only after you decide how you want scheduling.)

License
-------
MIT-style permissive use — adapt as needed.

Contact / Author
----------------
Script maintained by the original contributor (internal). Use the README as operational guidance and request changes or improvements in your internal repo/workflow.

---

Change log (high level)
-----------------------
- 2025-09-22: Added safer error handling, atomic Prometheus writes, restore workflow with dsctl fallback, ownership detection (chown to invoking user), DS_DB_PATH exposed as a top-level variable, and other small robustness improvements.

