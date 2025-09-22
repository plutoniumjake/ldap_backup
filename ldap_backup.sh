#!/usr/bin/env bash
# ldap backup and restore script (improved)
# - safer error handling
# - atomic writes for prometheus textfile collector
# - robust parsing and PID handling
# - new restore function that can use a specified file or the latest backup
#
# Usage:
#   ./ldap-backup-restore.sh -b
#   ./ldap-backup-restore.sh -r /backups/host/host_backup.2025-09-22.tar.gz.enc
#   ./ldap-backup-restore.sh -r           # restore latest
#   ./ldap-backup-restore.sh -h

set -o nounset
set -o pipefail
# don't set -e so we can handle errors gracefully and log them

PROGNAME=$(basename "$0")
DATESTRING=$(date +%Y-%m-%d)
LOGFILE="/var/log/${PROGNAME}.log"
BACKUP_DIR="/backups/$(hostname -s)"
TEXTFILE_COLLECTOR_DIR="/var/lib/node_exporter"
LDAP_SERVER=$(hostname -s)
AES_PASSWORD_FILE="${AES_PASSWORD_FILE:-/root/backup_tools/pass.pass}"
PID_FILE="${BACKUP_DIR}/${PROGNAME}.pid"
TMPDIR="$(mktemp -d /tmp/${PROGNAME}.XXXXXX || echo /tmp)"
PROM_TMP_SUFFIX="${TMPDIR}/node_file_database_dump.prom.$$"

# Logging helper
loggit () {
  local ts
  ts="$(date +%c)"
  echo "${ts} $*" >> "${LOGFILE}"
}

# Cleanup and exit
cleanup () {
  local exit_code=${1:-0}
  if [[ -n "${PID_FILE:-}" && -f "${PID_FILE}" ]]; then
    rm -f "${PID_FILE}"
  fi
  if [[ -d "${TMPDIR}" ]]; then
    rm -rf "${TMPDIR}"
  fi
  exit "${exit_code}"
}

dyingDeath () {
  loggit "FATAL: $*"
  echo "dying. check ${LOGFILE} for details."
  cleanup 1
}

# trap signals to ensure we remove pid file and tmpdir
trap 'loggit "Received signal, cleaning up."; cleanup 1' INT TERM HUP
trap 'cleanup $?' EXIT

# Ensure backup dir exists and is writable
ensure_backup_dir () {
  if [[ ! -d "${BACKUP_DIR}" ]]; then
    mkdir -p "${BACKUP_DIR}" || dyingDeath "Unable to create ${BACKUP_DIR}"
  fi

  # Determine the user who invoked the script:
  # Prefer SUDO_USER (the original user when run via sudo), otherwise use the current user.
  # If we can't determine a real user, fall back to root.
  if [[ -n "${SUDO_USER:-}" ]]; then
    owner_user="${SUDO_USER}"
  else
    owner_user="$(id -un 2>/dev/null || echo root)"
  fi

  # Ensure the user exists before attempting chown
  if id -u "${owner_user}" >/dev/null 2>&1; then
    owner_group="$(id -gn "${owner_user}" 2>/dev/null || echo "${owner_user}")"
    if chown "${owner_user}:${owner_group}" "${BACKUP_DIR}" 2>/dev/null; then
      loggit "Set owner of ${BACKUP_DIR} to ${owner_user}:${owner_group}"
    else
      loggit "Warning: failed to chown ${BACKUP_DIR} to ${owner_user}:${owner_group} (insufficient privileges?)"
    fi
  else
    loggit "Warning: determined owner ${owner_user} does not exist; leaving ${BACKUP_DIR} ownership unchanged"
  fi

  chmod 0755 "${BACKUP_DIR}" || true
}

backup_ldap () {
  ensure_backup_dir

  if [[ -f "${PID_FILE}" ]]; then
    dyingDeath "PID file ${PID_FILE} already exists. Another run may be in progress."
  fi
  echo $$ > "${PID_FILE}"

  local LDAP_BACKUP_DIR="${BACKUP_DIR}/$(hostname -s)_backup.${DATESTRING}"
  loggit "Stopping ldap and starting the backup."
  if ! /usr/bin/systemctl stop dirsrv@ldap.service; then
    loggit "Warning: failed to stop dirsrv service; continuing with backup attempt."
  fi

  if ! /usr/sbin/dsctl ldap db2bak "${LDAP_BACKUP_DIR}"; then
    loggit "db2bak failed."
    # try to restart service before exiting
    /usr/bin/systemctl start dirsrv@ldap.service || loggit "Warning: failed to start dirsrv service"
    cleanup 1
  fi

  loggit "Starting ldap."
  /usr/bin/systemctl start dirsrv@ldap.service || loggit "Warning: failed to start dirsrv service after backup"

  local DUMP_FILE_NAME="${LDAP_BACKUP_DIR}.tar.gz"
  loggit "Creating the tarball of ${LDAP_BACKUP_DIR} and /etc/dirsrv to ${DUMP_FILE_NAME}."
  if tar -zcf "${DUMP_FILE_NAME}" --absolute-names /etc/dirsrv "${LDAP_BACKUP_DIR}"; then
    loggit "Tarball created successfully; removing temporary backup directory ${LDAP_BACKUP_DIR}."
    rm -rf "${LDAP_BACKUP_DIR}"
  else
    loggit "Failed to create tarball ${DUMP_FILE_NAME}."
    cleanup 1
  fi

  # Encrypt
  loggit "Starting encryption of ${DUMP_FILE_NAME}."
  if [[ -f "${AES_PASSWORD_FILE}" ]]; then
    if openssl enc -salt -pass file:"${AES_PASSWORD_FILE}" -aes-128-cbc -pbkdf2 \
         -in "${DUMP_FILE_NAME}" -out "${DUMP_FILE_NAME}.enc"; then
      rm -f "${DUMP_FILE_NAME}"
      loggit "Encrypted to ${DUMP_FILE_NAME}.enc"
    else
      loggit "Encryption failed for ${DUMP_FILE_NAME}."
      cleanup 1
    fi
  else
    loggit "Encryption pass file not found at ${AES_PASSWORD_FILE}."
    dyingDeath "Encryption failed; pass file not found."
  fi

  # Update metrics and rotate
  write_the_scrape_file
  rotate_old_backups

  loggit "Backup complete."
  rm -f "${PID_FILE}"
}

# restore_ldap:
#   $1 -> path to .tar.gz.enc (optional). If omitted or "latest", will restore the latest backup in BACKUP_DIR.
# Behavior:
#   - decrypts backup using AES_PASSWORD_FILE
#   - extracts to tempdir
#   - if dsctl db2restore is available, uses it; otherwise tries to detect extracted backup dir and copy files (best-effort)
#   - restarts dirsrv service
restore_ldap () {
  local target="${1:-latest}"
  ensure_backup_dir

  # Choose file
  local enc_file=""
  if [[ "${target}" == "latest" ]]; then
    # find latest
    mapfile -t files < <(find "${BACKUP_DIR}" -type f -name '*tar.gz.enc' -printf "%T@ %p\n" 2>/dev/null | sort -n | awk '{print $2}')
    if (( ${#files[@]} == 0 )); then
      dyingDeath "No encrypted backups found in ${BACKUP_DIR}"
    fi
    enc_file="${files[-1]}"
  else
    enc_file="${target}"
    if [[ ! -f "${enc_file}" ]]; then
      dyingDeath "Restore file ${enc_file} does not exist."
    fi
  fi

  loggit "Restoring from ${enc_file}"

  if [[ ! -f "${AES_PASSWORD_FILE}" ]]; then
    dyingDeath "AES password file ${AES_PASSWORD_FILE} not found; cannot decrypt."
  fi

  local workdir
  workdir="$(mktemp -d "${TMPDIR}/restore.XXXXXX")" || dyingDeath "Unable to create workdir"
  local decrypted="${workdir}/restore.tar.gz"

  loggit "Decrypting ${enc_file} to ${decrypted}"
  if ! openssl enc -d -salt -pass file:"${AES_PASSWORD_FILE}" -aes-128-cbc -pbkdf2 -in "${enc_file}" -out "${decrypted}"; then
    loggit "Decryption failed for ${enc_file}"
    rm -rf "${workdir}"
    dyingDeath "Decryption failed"
  fi

  loggit "Extracting ${decrypted} into ${workdir}"
  if ! tar -zxf "${decrypted}" -C "${workdir}"; then
    loggit "Failed to extract ${decrypted}"
    rm -rf "${workdir}"
    dyingDeath "Extraction failed"
  fi

  # find the extracted db backup directory (the one created by dsctl db2bak)
  local extracted_backup_dir
  # Try to find a directory that matches <hostname>_backup.YYYY-MM-DD
  extracted_backup_dir=$(find "${workdir}" -maxdepth 2 -type d -name "$(hostname -s)_backup.*" | head -n1 || true)

  loggit "Stopping dirsrv service before restore"
  if ! /usr/bin/systemctl stop dirsrv@ldap.service; then
    loggit "Warning: failed to stop dirsrv service; continuing"
  fi

  if command -v dsctl >/dev/null 2>&1; then
    loggit "dsctl found. Attempting dsctl restore if supported."
    if [[ -n "${extracted_backup_dir}" ]]; then
      if /usr/sbin/dsctl ldap db2restore "${extracted_backup_dir}"; then
        loggit "dsctl db2restore completed successfully"
      else
        loggit "dsctl db2restore failed. Attempting best-effort file restore."
        # Fall through to file copy restore
      fi
    else
      loggit "No extracted backup dir found for dsctl db2restore, attempting best-effort file restore."
    fi
  else
    loggit "dsctl not present. Attempting best-effort file restore."
  fi

  # Best-effort file restore (only if dsctl restore didn't already happen)
  # If we extracted /etc/dirsrv and backup directory, restore them as appropriate
  # WARNING: This is a best-effort approach and should be validated in your environment.
  if [[ -d "${workdir}/etc/dirsrv" ]]; then
    loggit "Restoring /etc/dirsrv from archive (best-effort). Backup current /etc/dirsrv to ${workdir}/etc-dirsrv-before-restore"
    if [[ -d /etc/dirsrv ]]; then
      mv /etc/dirsrv "${workdir}/etc-dirsrv-before-restore" || loggit "Warning: failed to move existing /etc/dirsrv"
    fi
    cp -a "${workdir}/etc/dirsrv" /etc/dirsrv || loggit "Warning: failed to copy restored /etc/dirsrv to /etc/dirsrv"
  fi

  if [[ -n "${extracted_backup_dir}" && -d "${extracted_backup_dir}" ]]; then
    # try to copy db files back into place (best-effort)
    loggit "Attempting to restore database files from ${extracted_backup_dir} into the DS database location (best-effort)."
    # This path may vary — adjust to your environment
    local ds_db_path="/var/lib/dirsrv/slapd-ldap"
    if [[ -d "${ds_db_path}" ]]; then
      loggit "Backing up existing DS db directory ${ds_db_path} to ${workdir}/ds-before-restore"
      mv "${ds_db_path}" "${workdir}/ds-before-restore" || loggit "Warning: failed to backup existing DB dir"
      loggit "Copying restored DB files into ${ds_db_path}"
      cp -a "${extracted_backup_dir}" "${ds_db_path}" || loggit "Warning: failed to copy DB files; you may need to run dsctl db2restore manually"
    else
      loggit "DS db path ${ds_db_path} not present; skipping db file copy."
    fi
  fi

  loggit "Starting dirsrv service after restore"
  /usr/bin/systemctl start dirsrv@ldap.service || loggit "Warning: failed to start dirsrv service after restore"

  loggit "Restore process complete. Clean up workdir ${workdir}"
  rm -rf "${workdir}"
}

write_the_scrape_file () {
  mkdir -p "${TEXTFILE_COLLECTOR_DIR}" || loggit "Warning: failed to create ${TEXTFILE_COLLECTOR_DIR}"
  : > "${PROM_TMP_SUFFIX}"  # create/truncate temp file

  if [[ -d "${BACKUP_DIR}" ]]; then
    # safe find: if no files, array will be empty
    mapfile -t LDAP_BACKUPS < <(find "${BACKUP_DIR}" -type f -name '*tar.gz.enc' -printf "%T@ %p\n" 2>/dev/null | sort -n | awk '{print $2}')
    if (( ${#LDAP_BACKUPS[@]} > 0 )); then
      total_size=$(/usr/bin/du -bcs "${BACKUP_DIR}"/*.tar.gz.enc 2>/dev/null | tail -n1 | awk '{print $1}')
      : "${total_size:=0}"
      CURRENT_BACKUP_MTIME=$(stat -c %Y "${LDAP_BACKUPS[-1]}" 2>/dev/null || echo 0)
      CURRENT_BACKUP_SIZE=$(stat -c %s "${LDAP_BACKUPS[-1]}" 2>/dev/null || echo 0)
      echo "node_file_database_dump_count{database=\"${LDAP_SERVER}\"} ${#LDAP_BACKUPS[@]}" >> "${PROM_TMP_SUFFIX}"
      echo "node_file_database_dump_total_size_bytes{database=\"${LDAP_SERVER}\"} ${total_size}" >> "${PROM_TMP_SUFFIX}"
      echo "node_file_database_dump_latest_mtime{database=\"${LDAP_SERVER}\"} ${CURRENT_BACKUP_MTIME}" >> "${PROM_TMP_SUFFIX}"
      echo "node_file_database_dump_latest_size_bytes{database=\"${LDAP_SERVER}\"} ${CURRENT_BACKUP_SIZE}" >> "${PROM_TMP_SUFFIX}"
    else
      echo "node_file_database_dump_count{database=\"${LDAP_SERVER}\"} 0" >> "${PROM_TMP_SUFFIX}"
      echo "node_file_database_dump_total_size_bytes{database=\"${LDAP_SERVER}\"} 0" >> "${PROM_TMP_SUFFIX}"
      echo "node_file_database_dump_latest_mtime{database=\"${LDAP_SERVER}\"} 0" >> "${PROM_TMP_SUFFIX}"
      echo "node_file_database_dump_latest_size_bytes{database=\"${LDAP_SERVER}\"} 0" >> "${PROM_TMP_SUFFIX}"
    fi
  else
    echo "node_file_database_dump_count{database=\"${LDAP_SERVER}\"} 0" >> "${PROM_TMP_SUFFIX}"
    echo "node_file_database_dump_total_size_bytes{database=\"${LDAP_SERVER}\"} 0" >> "${PROM_TMP_SUFFIX}"
    echo "node_file_database_dump_latest_mtime{database=\"${LDAP_SERVER}\"} 0" >> "${PROM_TMP_SUFFIX}"
    echo "node_file_database_dump_latest_size_bytes{database=\"${LDAP_SERVER}\"} 0" >> "${PROM_TMP_SUFFIX}"
  fi

  # atomic move
  mv "${PROM_TMP_SUFFIX}" "${TEXTFILE_COLLECTOR_DIR}/node_file_database_dump.prom" || loggit "Warning: failed to move prometheus scrape file into place"
}

rotate_old_backups () {
  # keep 7 newest, delete older ones
  if [[ ! -d "${BACKUP_DIR}" ]]; then
    loggit "Backup dir ${BACKUP_DIR} does not exist; skipping rotation"
    return
  fi
  mapfile -t LDAP_BACKUPS_OLD < <(find "${BACKUP_DIR}" -type f -name '*tar.gz.enc' -printf "%T@ %p\n" 2>/dev/null | sort -n | awk '{print $2}' | head -n -7)
  if (( ${#LDAP_BACKUPS_OLD[@]} > 0 )); then
    for old_backup in "${LDAP_BACKUPS_OLD[@]}"; do
      loggit "Rotating out ${old_backup}."
      rm -f "${old_backup}" || loggit "Warning: failed to remove ${old_backup}"
    done
  else
    loggit "No old backups to rotate."
  fi
}

help_text () {
  cat <<EOF
Valid flags
  -b            Backup the ldap server, config, and schema.
  -r [file]     Restore from file. If file is omitted, the latest backup in ${BACKUP_DIR} will be used.
  -h            Print this help.
Environment:
  AES_PASSWORD_FILE   Path to the AES passphrase file (default: ${AES_PASSWORD_FILE})
EOF
}

# Argument parsing (simple, flexible)
if [[ $# -eq 0 ]]; then
  dyingDeath "Script called with no flags given."
fi

# Process args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--backup)
      backup_ldap
      shift
      ;;
    -r|--restore)
      # optional next argument is the file to restore
      if [[ $# -ge 2 && ! "$2" =~ ^- ]]; then
        restore_arg="$2"
        shift 2
      else
        restore_arg="latest"
        shift
      fi
      restore_ldap "${restore_arg}"
      ;;
    -h|--help)
      help_text
      exit 0
      ;;
    *)
      dyingDeath "Invalid flag given: $1"
      ;;
  esac
done

# explicit cleanup handled by trap EXIT