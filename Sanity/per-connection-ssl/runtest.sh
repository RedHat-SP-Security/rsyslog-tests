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

[[ -n "$TMT_TEST_NAME" ]] && driver=${TMT_TEST_NAME##*/}
driver=${driver-gtls}

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
    CleanupRegister 'rlRun "rlSEPortRestore"'
    rlRun "rlSEPortAdd tcp 50514-50517 syslogd_port_t" 0 "Enabling ports 50514-50516 in SElinux" 

    # Generate keys and certs
    for keys in '' 1 2; do
      rlRun "x509KeyGen ca${keys}"
      rlRun "x509KeyGen server${keys}"
      rlRun "x509KeyGen client${keys}"

      rlRun "x509SelfSign ca${keys}"
      rlRun "x509CertSign --CA ca${keys} server${keys}"
      rlRun "x509CertSign --CA ca${keys} client${keys}"

      rlRun "cp $(x509Cert ca${keys}) /etc/rsyslog.d/ca${keys}.pem"
      rlRun "cp $(x509Cert client${keys}) /etc/rsyslog.d/client${keys}-cert.pem"
      rlRun "cp $(x509Key client${keys}) /etc/rsyslog.d/client${keys}-key.pem"
      rlRun "cp $(x509Cert server${keys}) /etc/rsyslog.d/server${keys}-cert.pem"
      rlRun "cp $(x509Key server${keys}) /etc/rsyslog.d/server${keys}-key.pem"
    done

    rlRun "ls -l /etc/rsyslog.d"

    rsyslogConfigAppend "GLOBALS" <<EOF
      global(
          defaultNetstreamDriver="$driver"
          DefaultNetstreamDriverCAFile="/etc/rsyslog.d/ca.pem"
          DefaultNetstreamDriverCertFile="/etc/rsyslog.d/client-cert.pem"
          DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/client-key.pem"
      )
EOF

    rsyslogServerConfigAppend "GLOBALS" << EOF
      global(
          defaultNetstreamDriver="$driver"
          DefaultNetstreamDriverCAFile="/etc/rsyslog.d/ca.pem"
          DefaultNetstreamDriverCertFile="/etc/rsyslog.d/server-cert.pem"
          DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/server-key.pem"
      )
EOF

    rsyslogConfigAddTo "RULES" < <(rsyslogConfigCreateSection 'SSL')
    rsyslogServerConfigAddTo "MODULES" < <(rsyslogConfigCreateSection 'MODL')
    rsyslogServerConfigAddTo "RULES" < <(rsyslogConfigCreateSection 'RULESETS')
    rsyslogServerConfigAddTo "RULES" < <(rsyslogConfigCreateSection 'CONN1')
    rsyslogServerConfigAddTo "RULES" < <(rsyslogConfigCreateSection 'CONN2')
    rsyslogServerConfigAddTo "RULES" < <(rsyslogConfigCreateSection 'CONN3')

    rsyslogConfigReplace "SSL" << EOF
      local1.* action(
        type="omfwd"
        Protocol="tcp"
        Target="127.0.0.1"
        Port="50514"
        StreamDriver="$driver"
        StreamDriverMode="1"
        StreamDriverAuthMode="x509/certvalid"
      )

      local2.* action(
        type="omfwd"
        Protocol="tcp"
        Target="127.0.0.1"
        Port="50515"
        StreamDriver="$driver"
        StreamDriverMode="1"
        StreamDriverAuthMode="x509/certvalid"
        streamDriver.CAFile="/etc/rsyslog.d/ca1.pem"
        streamDriver.CertFile="/etc/rsyslog.d/client1-cert.pem"
        streamDriver.KeyFile="/etc/rsyslog.d/client1-key.pem"
      )

      local3.* action(
        type="omfwd"
        Protocol="tcp"
        Target="127.0.0.1"
        Port="50516"
        StreamDriver="$driver"
        StreamDriverMode="1"
        StreamDriverAuthMode="x509/certvalid"
        streamDriver.CAFile="/etc/rsyslog.d/ca2.pem"
        streamDriver.CertFile="/etc/rsyslog.d/client2-cert.pem"
        streamDriver.KeyFile="/etc/rsyslog.d/client2-key.pem"
      )

      local4.* action(
        type="omfwd"
        Protocol="tcp"
        Target="127.0.0.1"
        # connect to CONN2 (port 50515) causing the used certificate invalid
        Port="50515"
        StreamDriver="$driver"
        StreamDriverMode="1"
        StreamDriverAuthMode="x509/certvalid"
        streamDriver.CAFile="/etc/rsyslog.d/ca2.pem"
        streamDriver.CertFile="/etc/rsyslog.d/client2-cert.pem"
        streamDriver.KeyFile="/etc/rsyslog.d/client2-key.pem"
      )
EOF

    rsyslogServerConfigReplace "MODL" << EOF
      module(
        load="imtcp"
        StreamDriver.AuthMode="x509/certvalid"
        StreamDriver.Mode="1"
        StreamDriver.Name="$driver"
      )
EOF

    rsyslogServerConfigReplace "RULESETS" << EOF
      ruleset(name="TestRuleSet1"){
        *.*     $rsyslogServerLogDir/in1
      }
      ruleset(name="TestRuleSet2"){
        *.*     $rsyslogServerLogDir/in2
      }
      ruleset(name="TestRuleSet3"){
        *.*     $rsyslogServerLogDir/in3
      }
EOF

    rsyslogServerConfigReplace "CONN1" << EOF
      input(
        type="imtcp"
        Port="50514"
        ruleset="TestRuleSet1"
      )
EOF

    rsyslogServerConfigReplace "CONN2" << EOF
      input(
        type="imtcp"
        Port="50515"
        streamdriver.CAFile="/etc/rsyslog.d/ca1.pem"
        streamdriver.CertFile="/etc/rsyslog.d/server1-cert.pem"
        streamdriver.KeyFile="/etc/rsyslog.d/server1-key.pem"
        ruleset="TestRuleSet2"
      )
EOF

    rsyslogServerConfigReplace "CONN3" << EOF
      input(
        type="imtcp"
        Port="50516"
        streamDriver.CAFile="/etc/rsyslog.d/ca2.pem"
        streamDriver.CertFile="/etc/rsyslog.d/server2-cert.pem"
        streamDriver.KeyFile="/etc/rsyslog.d/server2-key.pem"
        ruleset="TestRuleSet3"
      )
EOF

    rlRun "rsyslogServerPrintEffectiveConfig -n"
    rlRun "rsyslogServerStart"
    rlRun "rsyslogServerStatus"
    rlRun "rsyslogPrintEffectiveConfig -n"
    rlRun "rsyslogServiceStart"
    rlRun "rsyslogServiceStatus"
    
    rlRun "> $rsyslogServerLogDir/messages"
  rlPhaseEnd; }

  tcfTry "Tests" --no-assert && {
    rlPhaseStartTest
      rlRun "logger 'test message'"
      rlRun "logger -p local1.info 'test message1'" 0 "send a message using a default keys/certs"
      rlRun "logger -p local2.info 'test message2'" 0 "send a message using a deciated keys/certs"
      rlRun "logger -p local3.info 'test message3'" 0 "send a message using a other deciated keys/certs"
      rlRun "logger -p local4.info 'test message4'" 0 "send a message using a wrong keys/certs"
      rlRun "sleep 3s"

      rlLog "'test message4' must not be delivered dues to the mismatch of the certificates"

      rlRun -s "cat $rsyslogServerLogDir/messages"
      rlAssertNotGrep "test message1" $rlRun_LOG
      rlAssertNotGrep "test message2" $rlRun_LOG
      rlAssertNotGrep "test message3" $rlRun_LOG
      rlAssertNotGrep "test message4" $rlRun_LOG

      tcfChk "check the message was delivered using the default keys/certs" && {
        rlRun -s "cat $rsyslogServerLogDir/in1"
        rlAssertGrep "test message1" $rlRun_LOG
        rlAssertNotGrep "test message2" $rlRun_LOG
        rlAssertNotGrep "test message3" $rlRun_LOG
        rlAssertNotGrep "test message4" $rlRun_LOG
      tcfFin; }

      tcfChk "check the message was delivered using the dedicated keys/certs" && {
        rlRun -s "cat $rsyslogServerLogDir/in2"
        rlAssertNotGrep "test message1" $rlRun_LOG
        rlAssertGrep "test message2" $rlRun_LOG
        rlAssertNotGrep "test message3" $rlRun_LOG
        rlAssertNotGrep "test message4" $rlRun_LOG
      tcfFin; }

      tcfChk "check the message was delivered using the other dedicated keys/certs" && {
        rlRun -s "cat $rsyslogServerLogDir/in3"
        rlAssertNotGrep "test message1" $rlRun_LOG
        rlAssertNotGrep "test message2" $rlRun_LOG
        rlAssertGrep "test message3" $rlRun_LOG
        rlAssertNotGrep "test message4" $rlRun_LOG
      tcfFin; }
    rlPhaseEnd;
  tcfFin; }

  rlPhaseStartCleanup && {
    rlRun "rsyslogServerStatus"
    rlRun "rsyslogServiceStatus"
    CleanupDo
    tcfCheckFinal
  rlPhaseEnd; }

  rlJournalPrintText
rlJournalEnd; }
