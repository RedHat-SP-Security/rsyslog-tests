#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /Regression/bz1886400-gnutls-shutdown-relp
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
    rlRun "certtool --generate-privkey --outfile ca-key.pem" 0 "Generate key for CA"
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
email = "root@$(hostname)
tls_www_server
EOF
    cat server.tmpl
    rlRun "certtool --generate-privkey --outfile server-key.pem --bits 2048" 0 "Generate key for server"
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
tls_www_server
EOF
    cat client.tmpl
    rlRun "certtool --generate-privkey --outfile client-key.pem --bits 2048" 0 "Generate key for client"
    rlRun "certtool --generate-request --template client.tmpl --load-privkey client-key.pem --outfile client-request.pem" 0 "Generate client cert request"
    rlRun "certtool --generate-certificate --template client.tmpl --load-request client-request.pem  --outfile client-cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem" 0 "Generate client cert"

    rlRun "mkdir -p /etc/rsyslogd.d && chmod 700 /etc/rsyslogd.d" 0 "Create /etc/rsyslogd.d"
    rlRun "cp *.pem /etc/rsyslogd.d/"
    rlRun "chmod 400 /etc/rsyslogd.d/* && restorecon -R /etc/rsyslogd.d"

    tcfChk "config client" && {
      rlRun "rsyslogPrepareConf"
      rsyslogConfigAddTo "MODULES" <<EOF
module(load="omrelp")
action(type="omrelp"
        target="$(hostname)"
        port="6514"
        timeout="10"
        tls="on"
        tls.caCert="/etc/rsyslogd.d/ca-cert.pem"
        tls.myCert="/etc/rsyslogd.d/client-cert.pem"
        tls.myPrivKey="/etc/rsyslogd.d/client-key.pem"
        tls.authmode="name"
        tls.permittedpeer=["$(hostname)"] )
EOF
      rlRun "rsyslogPrintEffectiveConfig -n"
    tcfFin; }

    tcfChk "config server" && {
      rsyslogServerConfigAddTo "MODULES" <<EOF
module(
    load="imrelp"
)
input(type="imrelp" port="6514"
  tls="on"
  tls.caCert="/etc/rsyslogd.d/ca-cert.pem"
  tls.myCert="/etc/rsyslogd.d/server-cert.pem"
  tls.myPrivKey="/etc/rsyslogd.d/server-key.pem"
  tls.authMode="name"
  tls.permittedpeer=["$(hostname)"]
)
EOF
      rlRun "rsyslogServerPrintEffectiveConfig -n"
    tcfFin; }

    rlRun "> $rsyslogServerLogDir/messages"
    rlRun "rsyslogServerStart"
    rlRun "rsyslogServiceStart"
    rlRun "rsyslogServiceStatus"
  rlPhaseEnd; }

  tcfTry "Tests" --no-assert && {
    rlPhaseStartTest && {
      rlRun "logger 'test message 1'"
      rlRun "sleep 3s"
      rlAssertGrep 'test message 1' $rsyslogServerLogDir/messages

      rlRun "iptables -I INPUT 1 -p tcp --dport 6514 -j DROP"
      rlRun "iptables -vnL INPUT"
      sleep 1
      t=$(date +%s)

      rlRun "logger 'test message 2'"
      rlRun "rsyslogServiceStop"
      rlAssertLesserOrEqual "service stop should not timeout" $(($(date +%s)-$t)) 20
      rlRun -s "rsyslogServiceStatus" 3
      rlAssertGrep "loaded" $rlRun_LOG
      rlAssertNotGrep "killed" $rlRun_LOG
      rm -f $rlRun_LOG
      rlRun "iptables -D INPUT 1"
    rlPhaseEnd; }; :
  tcfFin; }

  rlPhaseStartCleanup && {
    CleanupDo
    tcfCheckFinal
  rlPhaseEnd; }
  rlJournalPrintText
rlJournalEnd; }
