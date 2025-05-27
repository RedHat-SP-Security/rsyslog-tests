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
      rlRun "openssl genpkey -algorithm ${CRYPTO_ALGO} -out ca-key.pem"
      rlRun "openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 -subj \"${SUBJ_BASE}\" -addext \"basicConstraints=critical,CA:true\" -addext \"keyUsage=critical,keyCertSign,cRLSign\" -addext \"subjectAltName=DNS:${HOSTNAME},IP:127.0.0.1\" -addext \"crlDistributionPoints=URI:http://127.0.0.1/getcrl/\""
      # --- Server Certificate ---
      rlRun "openssl genpkey -algorithm ${CRYPTO_ALGO} -out server-key.pem"
      rlRun "openssl req -new -key server-key.pem -out server-request.pem -subj \"${SUBJ_BASE}\" -addext \"basicConstraints=CA:FALSE\" -addext \"keyUsage=digitalSignature,keyEncipherment\" -addext \"extendedKeyUsage=serverAuth\" -addext \"subjectAltName=DNS:${HOSTNAME},IP:127.0.0.1\""
      rlRun "openssl x509 -req -in server-request.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365 -set_serial 02 -copy_extensions copyall"
      # --- Client Certificate ---
      rlRun "openssl genpkey -algorithm ${CRYPTO_ALGO} -out client-key.pem"
      rlRun "openssl req -new -key client-key.pem -out client-request.pem -subj \"${SUBJ_BASE}\" -addext \"basicConstraints=CA:FALSE\" -addext \"keyUsage=digitalSignature\" -addext \"extendedKeyUsage=clientAuth\" -addext \"subjectAltName=DNS:${HOSTNAME},IP:127.0.0.1\""
      rlRun "openssl x509 -req -in client-request.pem -CA ca-cert.pem -CAkey ca-key.pem -CAserial ca.srl -out client-cert.pem -days 365 -set_serial 03 -copy_extensions copyall"
    # Usage of common asymetric algorithms
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
    rlRun "mkdir -p /etc/rsyslogd.d && chmod 700 /etc/rsyslogd.d" 0 "Create /etc/rsyslogd.d"
    rlRun "cp *.pem /etc/rsyslogd.d/"
    rlRun "chmod 400 /etc/rsyslogd.d/* && restorecon -R /etc/rsyslogd.d"

    client_config() {
      local options="$1"
      rsyslogConfigReplace "SSL" <<EOF
module(load="omrelp" tls.tlslib="openssl")
*.* action(type="omrelp"
    Target="127.0.0.1"
    Port="6514"
    tls="on"
    tls.cacert="/etc/rsyslogd.d/ca-cert.pem"
    tls.mycert="/etc/rsyslogd.d/client-cert.pem"
    tls.myprivkey="/etc/rsyslogd.d/client-key.pem"
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
    tls.cacert="/etc/rsyslogd.d/ca-cert.pem"
    tls.mycert="/etc/rsyslogd.d/server-cert.pem"
    tls.myprivkey="/etc/rsyslogd.d/server-key.pem"
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
