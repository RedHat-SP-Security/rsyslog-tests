#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rsyslog/Regression/bz1627799-RFE-Support-Intermediate-Certificate-Chains-in
#   Description: Test for BZ#1627799 ([RFE] Support Intermediate Certificate Chains in)
#   Author: Dalibor Pospisil <dapospis@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc.
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

driver=${driver:-gtls}

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


    cat > ca-root.tmpl <<EOF
organization = "Red Hat"
unit = "GSS"
locality = "Brno"
state = "Moravia"
country = CZ
cn = "rsyslog+chain+caroot"
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
    rlRun "certtool --generate-privkey --outfile ca-root-key.pem" 0 "Generate key for root CA"
    rlRun "certtool --generate-self-signed --load-privkey ca-root-key.pem --template ca-root.tmpl --outfile ca-root-cert.pem" 0 "Generate self-signed root CA cert"

    cat > ca2.tmpl <<EOF
organization = "Red Hat"
unit = "GSS"
locality = "Brno"
state = "Moravia"
country = CZ
cn = "rsyslog+chain+ca2"
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
    rlRun "certtool --generate-privkey --outfile ca2-key.pem" 0 "Generate key for CA2"
    rlRun "certtool --generate-request --template ca2.tmpl --load-privkey ca2-key.pem --outfile ca2-request.pem" 0 "Generate CA2 cert request"
    rlRun "certtool --generate-certificate --template ca2.tmpl --load-request ca2-request.pem  --outfile ca2-cert.pem --load-ca-certificate ca-root-cert.pem --load-ca-privkey ca-root-key.pem" 0 "Generate CA2 cert"

    cat > ca.tmpl <<EOF
organization = "Red Hat"
unit = "GSS"
locality = "Brno"
state = "Moravia"
country = CZ
cn = "rsyslog+chain+ca"
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
    rlRun "certtool --generate-privkey --outfile ca-key.pem" 0 "Generate key for CA"
    rlRun "certtool --generate-request --template ca.tmpl --load-privkey ca-key.pem --outfile ca-request.pem" 0 "Generate CA cert request"
    rlRun "certtool --generate-certificate --template ca.tmpl --load-request ca-request.pem  --outfile ca-cert.pem --load-ca-certificate ca2-cert.pem --load-ca-privkey ca2-key.pem" 0 "Generate CA cert"

    cat > server.tmpl <<EOF
organization = "Red Hat"
unit = "GSS"
locality = "Brno"
state = "Moravia"
country = CZ
cn = "rsyslog+chain+server"
serial = 002
expiration_days = 365
dns_name = "$(hostname)"
ip_address = "127.0.0.1"
email = "root@$(hostname)"
tls_www_server
EOF
    cat server.tmpl
    rlRun "certtool --generate-privkey --outfile server-key.pem --bits 2048" 0 "Generate key for server"
    rlRun "certtool --generate-request --template server.tmpl --load-privkey server-key.pem --outfile server-request.pem" 0 "Generate server cert request"
    rlRun "certtool --generate-certificate --template server.tmpl --load-request server-request.pem  --outfile server-cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem" 0 "Generate server cert"

    rlRun "mkdir -p /etc/rsyslogd.d && chmod 700 /etc/rsyslogd.d" 0 "Create /etc/rsyslogd.d"
    rlRun "cp *.pem /etc/rsyslogd.d/"
    rlRun "chmod 400 /etc/rsyslogd.d/* && restorecon -R /etc/rsyslogd.d"


    tcfChk "config client" && {
      rlRun "rsyslogPrepareConf"
      rsyslogConfigAppend "GLOBALS" <<EOF
global(
    DefaultNetstreamDriver="$driver"
    DefaultNetstreamDriverCAFile="/etc/rsyslogd.d/ca-root-cert.pem"
)
EOF

      rsyslogConfigAppend "MODULES" <<EOF
*.* action(type="omfwd"
    Protocol="tcp"
    Target="127.0.0.1"
    Port="6514"
    StreamDriver="$driver"
    StreamDriverMode="1"
    RebindInterval="50"
    StreamDriverAuthMode="x509/name"
    StreamDriverPermittedPeers="$(hostname)")
EOF
      rlRun "rsyslogPrintEffectiveConfig -n"
    tcfFin; }

    tcfChk "config server" && {
      rsyslogServerConfigAppend "MODULES" <<EOF
module(
    load="imtcp"
    StreamDriver.AuthMode="anon"
    StreamDriver.Mode="1"
    StreamDriver.Name="$driver"
)
input(type="imtcp" Port="6514")
EOF
      rsyslogServerConfigAppend "GLOBALS" <<EOF
global(
    DefaultNetstreamDriver="$driver"
    DefaultNetstreamDriverCAFile="/etc/rsyslogd.d/ca-cert.pem"
    DefaultNetstreamDriverCertFile="/etc/rsyslogd.d/server-cert.pem"
    DefaultNetstreamDriverKeyFile="/etc/rsyslogd.d/server-key.pem"
    #EXTRACA
)
EOF
      rlRun "rsyslogServerPrintEffectiveConfig -n"
    tcfFin; }

    rlRun "> $rsyslogServerLogDir/messages"
    rlRun "rsyslogServerStart"
    rlRun "rsyslogServiceStart"
  rlPhaseEnd; }

  tcfTry "Tests" --no-assert && {
    rlPhaseStartTest && {
      rlRun "echo 'ahoj' | openssl s_client -CAfile ca-root-cert.pem -port 6514"
      rlRun "logger 'test message'"
      rlRun "sleep 3s"
      rlRun "journalctl | grep -v 'test message'"
      rlRun "rsyslogServiceStop"
      rlRun "rsyslogServerStop"
      rlRun "> $rsyslogServerLogDir/messages"
      if [[ "${extraCA,,}" == "true" ]];
      then
        # Enable Extra CA Files (only for SSL)
        rlRun "sed -i 's|#EXTRACA|NetstreamDriverCAExtraFiles=\"/etc/rsyslogd.d/ca2-cert.pem\"|' $rsyslogServerConf"
      else
        rlRun "cat server-cert.pem ca-cert.pem ca2-cert.pem > /etc/rsyslogd.d/server-cert.pem"
        rlRun "chmod 400 /etc/rsyslogd.d/* && restorecon -R /etc/rsyslogd.d"
      fi
      rlRun "rsyslogServerStart"
      rlRun "rsyslogServiceStart"
      rlRun "rsyslogServerPrintEffectiveConfig -n"
      rlRun "echo 'ahoj' | openssl s_client -CAfile ca-root-cert.pem -port 6514"
      rlRun "logger 'test message'"
      rlRun "sleep 3s"
      rlRun "journalctl | grep 'test message'"
    rlPhaseEnd; }
  tcfFin; }

  rlPhaseStartCleanup && {
    CleanupDo
    tcfCheckFinal
  rlPhaseEnd; }
  rlJournalPrintText
rlJournalEnd; }
