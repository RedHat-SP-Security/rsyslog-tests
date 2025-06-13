#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /Sanity/openssl-parameters
#   Author: Dalibor Pospisil <dapospis@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2021 Red Hat, Inc.
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

# Include Beaker environment
. /usr/bin/rhts-environment.sh || :
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="rsyslog"

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
    #Usage of PQC sign algorithms
    if rlIsRHEL '>=10.1'; then
      rlLog "Generating certificates using the rsyslog crypto key generation function"
      HOSTNAME=$(hostname)
      ORG="Red Hat"
      OU_GSS="GSS"
      LOCALITY="Brno"
      STATE="Moravia"
      COUNTRY="CZ"
      CN_COMMON="rsyslog\+openssl"
      EMAIL_ADDR="root@${HOSTNAME}"
      SUBJ_BASE="/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORG}/OU=${OU_GSS}/CN=${CN_COMMON}/emailAddress=${EMAIL_ADDR}"
      # --- CA Certificate ---
      rsyslogGeneratePrivateKey "ca-key.pem" "${CRYPTO_ALGO}"
      declare -a ca_extensions=(
          "subjectAltName=DNS:${HOSTNAME},IP:127.0.0.1"
          "crlDistributionPoints=URI:http://127.0.0.1/getcrl/"
      )
      rsyslogCreateSelfSignedCa "ca-key.pem" "ca-cert.pem" "${SUBJ_BASE}" 365 ca_extensions

      # --- Server Certificate ---
      rsyslogGeneratePrivateKey "server-key.pem" "${CRYPTO_ALGO}"
      declare -a server_extensions=(
          "basicConstraints=CA:FALSE"
          "keyUsage=digitalSignature,keyEncipherment"
          "extendedKeyUsage=serverAuth"
          "subjectAltName=DNS:${HOSTNAME},IP:127.0.0.1"
      )
      rsyslogCreateCsr "server-key.pem" "server-request.pem" "${SUBJ_BASE}" server_extensions
      # Note the empty params for unused config_path/extensions, and "yes" to copy extensions from the CSR
      rsyslogSignCertificate "server-request.pem" "ca-cert.pem" "ca-key.pem" "server-cert.pem" 365 "" "" "yes"

      # --- Client Certificate ---
      rsyslogGeneratePrivateKey "client-key.pem" "${CRYPTO_ALGO}"
      declare -a client_extensions=(
          "basicConstraints=CA:FALSE"
          "keyUsage=digitalSignature"
          "extendedKeyUsage=clientAuth"
          "subjectAltName=DNS:${HOSTNAME},IP:127.0.0.1"
      )
      rsyslogCreateCsr "client-key.pem" "client-request.pem" "${SUBJ_BASE}" client_extensions
      # Note: The original test used -CAserial ca.srl here. For consistency, -CAcreateserial is used by the library.
      # This is generally safe and often preferred.
      rsyslogSignCertificate "client-request.pem" "ca-cert.pem" "ca-key.pem" "client-cert.pem" 365 "" "" "yes"
    elif rlIsRHEL '<10.1'; then
      TLSv1_3_EXLUCED="-TLSv1.3"

      cat > ca.tmpl <<EOF
organization = "Red Hat"
unit = "GSS"
locality = "Brno"
state = "Moravia"
country = CZ
cn = "rsyslog+gnutls"
serial = 001
expiration_days = 365
dns_name = "$(hostname)"
ip_address = "127.0.0.1"
email = "root@$(hostname)"
crl_dist_points = "http://127.0.0.1/getcrl/"
ca
cert_signing_key
crl_signing_key
EOF
      rlRun "certtool --generate-privkey  --key-type ${CRYPTO_ALGO} --outfile ca-key.pem" 0 "Generate key for CA"
      rlRun "certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem" 0 "Generate self-signed CA cert"

    cat > server.tmpl <<EOF
organization = "Red Hat"
unit = "GSS"
locality = "Brno"
state = "Moravia"
country = CZ
cn = "rsyslog+gnutls"
serial = 002
expiration_days = 365
dns_name = "$(hostname)"
ip_address = "127.0.0.1"
email = "root@$(hostname)"
tls_www_server
EOF
      cat server.tmpl
      rlRun "certtool --generate-privkey --key-type ${CRYPTO_ALGO} --outfile server-key.pem" 0 "Generate key for server"
      rlRun "certtool --generate-request --template server.tmpl --load-privkey server-key.pem --outfile server-request.pem" 0 "Generate server cert request"
      rlRun "certtool --generate-certificate --template server.tmpl --load-request server-request.pem  --outfile server-cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem" 0 "Generate server cert"

    cat > client.tmpl <<EOF
organization = "Red Hat"
unit = "GSS"
locality = "Brno"
state = "Moravia"
country = CZ
cn = "rsyslog+gnutls"
serial = 003
expiration_days = 365
dns_name = "$(hostname)"
ip_address = "127.0.0.1"
email = "root@$(hostname)"
tls_www_client
EOF
      cat client.tmpl
      rlRun "certtool --generate-privkey --key-type ${CRYPTO_ALGO} --outfile client-key.pem" 0 "Generate key for client"
      rlRun "certtool --generate-request --template client.tmpl --load-privkey client-key.pem --outfile client-request.pem" 0 "Generate client cert request"
      rlRun "certtool --generate-certificate --template client.tmpl --load-request client-request.pem  --outfile client-cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem" 0 "Generate client cert"
    fi
    rlRun "mkdir -p /etc/rsyslog.d && chmod 700 /etc/rsyslog.d" 0 "Create /etc/rsyslog.d"
    rlRun "cp *.pem /etc/rsyslog.d/"
    rlRun "chmod 400 /etc/rsyslog.d/* && restorecon -R /etc/rsyslog.d"

    client_config() {
      local options="$1"
      rsyslogConfigReplace "SSL" <<EOF
module(load="omrelp" tls.tlslib="openssl")
*.* action(type="omrelp"
    Target="127.0.0.1"
    Port="6514"
    tls="on"
    tls.cacert="/etc/rsyslog.d/ca-cert.pem"
    tls.mycert="/etc/rsyslog.d/client-cert.pem"
    tls.myprivkey="/etc/rsyslog.d/client-key.pem"
    tls.authmode="certvalid"
    tls.permittedpeer="$(hostname)"
    $options
    )
EOF
      rlRun "rsyslogPrintEffectiveConfig -n"
    }

    tcfChk "config client" && {
      rlRun "rsyslogPrepareConf"
      rsyslogConfigAddTo "MODULES" < <(rsyslogConfigCreateSection 'SSL')
    tcfFin; }

    server_config() {
      local options="$1"
      rsyslogServerConfigReplace "SSL" <<EOF
module(
    load="imrelp"
    tls.tlslib="openssl"
)
input(type="imrelp" Port="6514"
    tls="on"
    tls.cacert="/etc/rsyslog.d/ca-cert.pem"
    tls.mycert="/etc/rsyslog.d/server-cert.pem"
    tls.myprivkey="/etc/rsyslog.d/server-key.pem"
    tls.authmode="certvalid"
    tls.permittedpeer="$(hostname)"
    $options
)
EOF
      rlRun "rsyslogServerPrintEffectiveConfig -n"
    }

    tcfChk "config server" && {
      rsyslogServerConfigAddTo "MODULES" < <(rsyslogConfigCreateSection 'SSL')
    tcfFin; }

    rlRun "> $rsyslogServerLogDir/messages"
  rlPhaseEnd; }

  tcfTry "Tests" --no-assert && {
    rlPhaseStartTest "client" && tcfChk && {
      tcfChk "setup" && {
        client_config "tls.tlscfgcmd=\"Protocol=ALL,-SSLv2,-SSLv3,-TLSv1,-TLSv1.2,${TLSv1_3_EXLUCED}\""
        server_config
        > $rsyslogServerLogDir/messages
        rlRun "rsyslogServerStart"
        rlRun -s "rsyslogServerStatus"
        rlAssertGrep "rsyslogd" $rlRun_LOG
        rlAssertNotGrep "ignored" $rlRun_LOG
        rm -f $rlRun_LOG
        rlRun "rsyslogServiceStart"
        rlRun -s "rsyslogServiceStatus"
        rlAssertGrep "rsyslogd" $rlRun_LOG
        rlAssertNotGrep "ignored" $rlRun_LOG
        rm -f $rlRun_LOG
      tcfFin; }
      tcfTry "test" && {
        rlRun "tshark -i any -f 'tcp port 6514' -a 'filesize:100' -w wireshark.dump 2>tshark.stderr &" 0 "Running wireshark"
        TSHARK_PID=$!
        sleep 1
        rlRun "logger 'test message'"
        rlRun "sleep 3s"
        rlAssertGrep 'test message' $rsyslogServerLogDir/messages
        ps -p $TSHARK_PID &> /dev/null && kill $TSHARK_PID; sleep 3
        rlRun "cat tshark.stderr"
        rlRun "rm -f tshark.stderr"
        rlRun "tshark -V -r wireshark.dump | grep 'test message'" 1 "wireshark log should not contain unencrypted message"; :
      tcfFin; }
    rlPhaseEnd; tcfFin; }

    rlPhaseStartTest "server" && tcfChk && {
      tcfChk "setup" && {
        client_config
        server_config "tls.tlscfgcmd=\"Protocol=ALL,-SSLv2,-SSLv3,-TLSv1,-TLSv1.2,${TLSv1_3_EXLUCED}\""
        > $rsyslogServerLogDir/messages
        rlRun "rsyslogServerStart"
        rlRun -s "rsyslogServerStatus"
        rlAssertGrep "rsyslogd" $rlRun_LOG
        rlAssertNotGrep "ignored" $rlRun_LOG
        rm -f $rlRun_LOG
        rlRun "rsyslogServiceStart"
        rlRun -s "rsyslogServiceStatus"
        rlAssertGrep "rsyslogd" $rlRun_LOG
        rlAssertNotGrep "ignored" $rlRun_LOG
        rm -f $rlRun_LOG
      tcfFin; }
      tcfTry "test" && {
        rlRun "tshark -i any -f 'tcp port 6514' -a 'filesize:100' -w wireshark.dump 2>tshark.stderr &" 0 "Running wireshark"
        TSHARK_PID=$!
        sleep 1
        rlRun "logger 'test message'"
        rlRun "sleep 3s"
        rlAssertGrep 'test message' $rsyslogServerLogDir/messages
        ps -p $TSHARK_PID &> /dev/null && kill $TSHARK_PID; sleep 3
        rlRun "cat tshark.stderr"
        rlRun "rm -f tshark.stderr"
        rlRun "tshark -V -r wireshark.dump | grep 'test message'" 1 "wireshark log should not contain unencrypted message"; :
      tcfFin; }
    rlPhaseEnd; tcfFin; }

    :
  tcfFin; }

  rlPhaseStartCleanup && {
    CleanupDo
    tcfCheckFinal
  rlPhaseEnd; }
  rlJournalPrintText
rlJournalEnd; }
