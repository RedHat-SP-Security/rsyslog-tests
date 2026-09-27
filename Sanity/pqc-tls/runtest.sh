#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /Sanity/pqc-tls
#   Description: PQC TLS sanity — ML-DSA-65 certificates and ML-KEM hybrid key exchange
#   Author: Attila Lakatos <alakatos@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2026 Red Hat, Inc.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

. /usr/bin/rhts-environment.sh || :
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="rsyslog"
CERTDIR="/etc/rsyslog.d"
PORT="6514"

# Returns driver-specific TLS option string for the given role.
# Args: $1=driver (gtls|ossl), $2=role (pqc|classical|hybrid)
#
#   pqc      — PQC KEM groups only (X25519MLKEM768); no classical fallback
#   classical — classical KEM groups only (X25519, P-256/SECP256R1); no PQC
#   hybrid    — PQC preferred with classical fallback (X25519MLKEM768 + X25519)
#
# GnuTLS uses -GROUP-ALL to wipe all groups then selectively restores only what
# is needed. ossl uses OpenSSL SSL_CONF_cmd format via gnutlsPriorityString.
# See: https://docs.rsyslog.com/doc//tutorials/post_quantum_tls.html
get_tls_opts() {
    local driver="$1" role="$2"
    case "${driver}:${role}" in
        "ossl:pqc")
            echo 'gnutlsPriorityString="MinProtocol=TLSv1.3\nGroups=X25519MLKEM768"'
            ;;
        "ossl:classical")
            echo 'gnutlsPriorityString="MinProtocol=TLSv1.3\nGroups=X25519:P-256"'
            ;;
        "ossl:hybrid")
            echo 'gnutlsPriorityString="MinProtocol=TLSv1.3\nGroups=X25519MLKEM768:X25519"'
            ;;
        "gtls:pqc")
            echo 'gnutlsPriorityString="NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519-MLKEM768"'
            ;;
        "gtls:classical")
            echo 'gnutlsPriorityString="NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1"'
            ;;
        "gtls:hybrid")
            echo 'gnutlsPriorityString="NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519-MLKEM768:+GROUP-X25519"'
            ;;
        *)
            rlDie "Unsupported driver/role combination: ${driver}:${role}"
            ;;
    esac
}

# KEM negotiation scenario matrix — all 9 combinations of (pqc, classical, hybrid).
# Format per entry: server_kem:client_kem:expected_rc:expected_grp
#   expected_rc  — 0: message must be delivered; 1: must not be delivered
#   expected_grp — openssl s_client "Negotiated TLS1.3 group:" value to assert;
#                  empty means no group check (classical X25519 or failed connection)
KEM_SCENARIOS=(
    "pqc:pqc:0:X25519MLKEM768"
    "pqc:classical:1:"
    "pqc:hybrid:0:X25519MLKEM768"
    "hybrid:pqc:0:X25519MLKEM768"
    "hybrid:classical:0:"
    "hybrid:hybrid:0:X25519MLKEM768"
    "classical:classical:0:"
    "classical:pqc:1:"
    "classical:hybrid:0:"
)

# Verify that the public key embedded in a certificate matches the private key,
# then display the full certificate text for the test log.
# Args: $1=cert_file, $2=key_file, $3=label
verify_cert_key_pair() {
    local cert="$1" key="$2" label="$3"
    local cert_pub key_pub
    cert_pub=$(openssl x509 -noout -pubkey -in "${cert}" | sha256sum)
    key_pub=$(openssl pkey -pubout -in "${key}" | sha256sum)
    rlAssertEquals "${label}: public key in cert matches private key" \
        "${cert_pub}" "${key_pub}"
    rlRun "openssl x509 -in '${cert}' -text -noout" 0 "Show ${label} certificate"
}

# Generate CA, server, and client certificates for the current CERT_ALG,
# verify each key pair, and install everything into CERTDIR.
prepare_certificates() {
    rsyslogGeneratePrivateKey "ca.key" "${CERT_ALG}"
    rsyslogCreateSelfSignedCa "ca.key" "ca.pem" "/CN=pqc-test-ca" 365

    rsyslogGeneratePrivateKey "server.key" "${CERT_ALG}"
    declare -a server_exts=(
        "basicConstraints=CA:FALSE"
        "keyUsage=digitalSignature"
        "extendedKeyUsage=serverAuth"
        "subjectAltName=DNS:$(hostname),IP:127.0.0.1"
    )
    rsyslogCreateCsr "server.key" "server.csr" "/CN=$(hostname)" server_exts
    rsyslogSignCertificate "server.csr" "ca.pem" "ca.key" "server.pem" 365 "" "" "yes"

    rsyslogGeneratePrivateKey "client.key" "${CERT_ALG}"
    declare -a client_exts=(
        "basicConstraints=CA:FALSE"
        "keyUsage=digitalSignature"
        "extendedKeyUsage=clientAuth"
        "subjectAltName=DNS:$(hostname),IP:127.0.0.1"
    )
    rsyslogCreateCsr "client.key" "client.csr" "/CN=$(hostname)" client_exts
    rsyslogSignCertificate "client.csr" "ca.pem" "ca.key" "client.pem" 365 "" "" "yes"

    rlRun "rm -f ./*.csr" 0 "Remove intermediate CSR files"

    verify_cert_key_pair "ca.pem"     "ca.key"     "CA"
    verify_cert_key_pair "server.pem" "server.key" "server"
    verify_cert_key_pair "client.pem" "client.key" "client"

    rlRun "mkdir -p ${CERTDIR} && chmod 700 ${CERTDIR}"
    rlRun "cp ./*.pem ./*.key ${CERTDIR}/"
    rlRun "chmod 400 ${CERTDIR}/* && restorecon -R ${CERTDIR}"
    rlRun "ls -l ${CERTDIR}" 0 "List installed certificates and keys"
}

# Reconfigure the server-side rsyslog imtcp input.
# Args: $1=driver (gtls|ossl), $2=tls_opts_string
configure_server() {
    local driver="$1" tls_opts="$2"
    rsyslogServerConfigReplace "IMTCP" <<EOF
module(load="imtcp")
input(type="imtcp"
    port="${PORT}"
    StreamDriver.Name="${driver}"
    StreamDriver.Mode="1"
    StreamDriver.AuthMode="x509/name"
    PermittedPeer="$(hostname)"
    StreamDriver.CAFile="${CERTDIR}/ca.pem"
    StreamDriver.CertFile="${CERTDIR}/server.pem"
    StreamDriver.KeyFile="${CERTDIR}/server.key"
    ${tls_opts}
)
EOF
    rlRun "rsyslogServerPrintEffectiveConfig -n"
}

# Reconfigure the client-side rsyslog omfwd action.
# Per-action cert overrides are used so GLOBALS never need to change between scenarios.
# Args: $1=driver, $2=ca_filename, $3=cert_filename, $4=key_filename, $5=tls_opts_string
configure_client() {
    local driver="$1" ca="$2" cert="$3" key="$4" tls_opts="$5"
    rsyslogConfigReplace "SSL" <<EOF
*.* action(
    type="omfwd"
    Protocol="tcp"
    Target="127.0.0.1"
    Port="${PORT}"
    StreamDriver="${driver}"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
    StreamDriverPermittedPeers="$(hostname)"
    streamDriver.CAFile="${CERTDIR}/${ca}"
    streamDriver.CertFile="${CERTDIR}/${cert}"
    streamDriver.KeyFile="${CERTDIR}/${key}"
    ${tls_opts}
)
EOF
    rlRun "rsyslogPrintEffectiveConfig -n"
}

# Assert message delivery outcome and (optionally) the negotiated TLS group.
# Args: $1=msg, $2=logfile, $3=expected_rc (0=delivered, 1=not delivered), $4=expected_grp (or empty)
verify_kem_scenario() {
    local msg="$1" logfile="$2" expected_rc="$3" expected_grp="$4"
    local delivered

    rlRun "logger '${msg}'"
    rlWaitForMessage "${msg}" "${logfile}" 15
    delivered=$?
    rlAssertEquals "Message delivery (expected rc: ${expected_rc})" "${delivered}" "${expected_rc}"
    rlRun "rsyslogCatLogFileFromPointer ${logfile}"

    [ -z "${expected_grp}" ] && return 0

    rlRun -s "openssl s_client -connect 127.0.0.1:${PORT} \
        -CAfile ${CERTDIR}/ca.pem \
        -cert   ${CERTDIR}/client.pem \
        -key    ${CERTDIR}/client.key \
        -groups ${expected_grp} \
        </dev/null 2>&1" 0,1 "Probe negotiated TLS group"
    rlAssertGrep "Negotiated TLS1.3 group: ${expected_grp}" "$rlRun_LOG"
}

# Wait up to MAX_WAIT seconds for MSG to appear in LOGFILE.
# Remove once rlWaitForMessage is available from the installed library package.
# Args: $1=msg_string, $2=logfile_path, $3=max_wait_seconds (default 15)
rlWaitForMessage() {
    local msg="$1" logfile="$2" max_wait="${3:-15}"
    local i
    for i in $(seq 1 "${max_wait}"); do
        grep -qF "${msg}" "${logfile}" && {
            rlLog "Message delivered after ${i}s"
            return 0
        }
        sleep 1
    done
    return 1
}

rlJournalStart && {
  rlPhaseStartSetup && {
    rlRun "rlCheckRecommended; rlCheckRequired" || rlDie "cannot continue"
    rlRun "rlImport --all" 0 "Import libraries" || rlDie "cannot continue"
    CleanupRegister 'rlRun "rsyslogCleanup"'
    rlRun "rsyslogSetup"
    CleanupRegister 'rlRun "rsyslogServerCleanup"'
    rlRun "rsyslogServerSetup"
    rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
    CleanupRegister "rlRun 'rm -r $TmpDir' 0 'Removing tmp directory'"
    CleanupRegister 'rlRun "popd"'
    rlRun "pushd $TmpDir"

    # -----------------------------------------------------------------------
    # Runtime capability checks
    # -----------------------------------------------------------------------
    rlRun "openssl list -kem-algorithms | grep -q 'X25519MLKEM768'" 0 \
        "Verify X25519MLKEM768 KEM support (requires OpenSSL 3.5+)" \
        || rlDie "X25519MLKEM768 not available on this system"

    if [ "${CERT_ALG}" = "ML-DSA-65" ]; then
        rlRun "openssl list -signature-algorithms | grep -i 'ML-DSA-65'" 0 \
            "Verify native ML-DSA-65 support (requires OpenSSL 3.5+)" \
            || rlDie "ML-DSA-65 not available on this system"
    fi

    # Log available algorithms for diagnostic purposes — no parsing, no conditional logic.
    rlRun "openssl list -kem-algorithms" 0,1 "List available OpenSSL KEM algorithms"
    rlRun "gnutls-cli --list | grep -E '^(Groups|Public Key Systems|PK-signatures):'" \
        0,1 "List GnuTLS KEM groups, public key systems, and PK-signatures"

    prepare_certificates

    # -----------------------------------------------------------------------
    # Prepare client config skeleton (SSL section replaced per scenario)
    # -----------------------------------------------------------------------
    rlRun "rsyslogPrepareConf"
    rsyslogConfigAddTo --begin "RULES" < <(rsyslogConfigCreateSection 'SSL')

    # -----------------------------------------------------------------------
    # Prepare server config skeleton (IMTCP section replaced per scenario)
    # -----------------------------------------------------------------------
    rsyslogServerConfigAddTo "RULES" < <(rsyslogConfigCreateSection 'IMTCP')

    rsyslogResetLogFilePointer "$rsyslogServerLogDir/messages"
  rlPhaseEnd; }

  # =========================================================================
  # KEM negotiation matrix — all 9 combinations of (pqc, classical, hybrid)
  # =========================================================================
  for scenario in "${KEM_SCENARIOS[@]}"; do
    IFS=: read -r srv_kem cli_kem expected_rc expected_grp <<< "${scenario}"
    phase_name="server: kem=${srv_kem} driver=${SERVER_DRIVER} | client: kem=${cli_kem} driver=${CLIENT_DRIVER} | expected_rc=${expected_rc} expected_grp=${expected_grp}"

    rlPhaseStartTest "${phase_name}" && {
      rlRun "rsyslogServiceStop" 0,1 "Stop client rsyslog"
      rlRun "rsyslogServerStop"  0,1 "Stop server rsyslog"
      rsyslogResetLogFilePointer "$rsyslogServerLogDir/messages"
      configure_server "${SERVER_DRIVER}" "$(get_tls_opts "${SERVER_DRIVER}" "${srv_kem}")"
      configure_client "${CLIENT_DRIVER}" \
          "ca.pem" "client.pem" "client.key" \
          "$(get_tls_opts "${CLIENT_DRIVER}" "${cli_kem}")"
      rlRun "rsyslogServerStart" && rlRun "rsyslogServerStatus"
      rlRun "rsyslogServiceStart" && rlRun "rsyslogServiceStatus"

      msg="test srv_kem=${srv_kem} cli_kem=${cli_kem} cert=${CERT_ALG} srv_drv=${SERVER_DRIVER} cli_drv=${CLIENT_DRIVER}"

      verify_kem_scenario "${msg}" "$rsyslogServerLogDir/messages" "${expected_rc}" "${expected_grp}"
    rlPhaseEnd; }
  done

  rlPhaseStartCleanup && {
    CleanupDo
  rlPhaseEnd; }
  rlJournalPrintText
rlJournalEnd; }
