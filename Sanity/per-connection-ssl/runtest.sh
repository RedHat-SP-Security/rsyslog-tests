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

if [ "${DRIVER_GTLS}" != "YES" ] ; then
  # Get the part of the path before the last component (e.g., "/Sanity/per-connection-ssl/ossl")
  parent_path=$(dirname "$TMT_TEST_NAME")
  # Get the last component of that result, which is the driver name (e.g., "ossl")
  [[ -n "$TMT_TEST_NAME" ]] && driver=$(basename "$parent_path")
else
  driver="gtls"
fi

# This conditional logic is syntactically correct in Bash.
# rlIsRHEL is a BeakerLib function, assumed to work as intended.
# driver == "ossl" is a valid string comparison within [[ ... ]].
if [ "${CRYPTO_ALG}" == "ML-DSA-65" ] && [ "${driver}" == "ossl" ] ; then
  rlLog "Adjust rsyslog configuration to use particular version of TLS due PQC key exchange."
  # This line has several problems for its likely intended use:
  TLS_VER="gnutlsPriorityString=\"Protocol=ALL,-SSLv2,-SSLv3,-TLSv1,-TLSv1.2\""
fi
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
    # Generate 3 full sets of keys and certificates using the library
    for keys in '' 1 2; do
      rlLog "Generating certificate chain for suffix: '${keys}'"

      # 1. Generate all private keys
      rsyslogGeneratePrivateKey "ca${keys}.key" "${CRYPTO_ALG}"
      rsyslogGeneratePrivateKey "server${keys}.key" "${CRYPTO_ALG}"
      rsyslogGeneratePrivateKey "client${keys}.key" "${CRYPTO_ALG}"

      # 2. Create the self-signed CA certificate
      rsyslogCreateSelfSignedCa "ca${keys}.key" "ca${keys}.pem" "/CN=ca${keys}"

      # 3. Create and sign the server certificate
      rsyslogCreateCsr "server${keys}.key" "server${keys}.csr" "/CN=server${keys}"
      rsyslogSignCertificate "server${keys}.csr" "ca${keys}.pem" "ca${keys}.key" "server${keys}.pem"

      # 4. Create and sign the client certificate
      rsyslogCreateCsr "client${keys}.key" "client${keys}.csr" "/CN=client${keys}"
      rsyslogSignCertificate "client${keys}.csr" "ca${keys}.pem" "ca${keys}.key" "client${keys}.pem"

      # 5. Clean up intermediate CSR files
      rlRun "rm ./*${keys}.csr" 0 "Clean up CSR files"

      # 6. Copy the final keys and certificates to the rsyslog config directory
      rlRun "cp ca${keys}.pem /etc/rsyslog.d/ca${keys}.pem"
      rlRun "cp client${keys}.pem /etc/rsyslog.d/client${keys}-cert.pem"
      rlRun "cp client${keys}.key /etc/rsyslog.d/client${keys}-key.pem"
      rlRun "cp server${keys}.pem /etc/rsyslog.d/server${keys}-cert.pem"
      rlRun "cp server${keys}.key /etc/rsyslog.d/server${keys}-key.pem"

      # 7. Add server cert to the system trust store
      rlRun "cp /etc/rsyslog.d/server${keys}-cert.pem /etc/pki/ca-trust/source/anchors/server${keys}-cert.pem"
    done

    # 8. Update the system trust store once after all certs are copied
    rlRun "update-ca-trust"
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
        ${TLS_VER}
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
        ${TLS_VER}
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
        ${TLS_VER}
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
        ${TLS_VER}
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
        *.* $rsyslogServerLogDir/in1
      }
      ruleset(name="TestRuleSet2"){
        *.* $rsyslogServerLogDir/in2
      }
      ruleset(name="TestRuleSet3"){
        *.* $rsyslogServerLogDir/in3
      }
EOF

    rsyslogServerConfigReplace "CONN1" << EOF
      input(
        type="imtcp"
        Port="50514"
        ruleset="TestRuleSet1"
        ${TLS_VER}
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
        ${TLS_VER}
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
        ${TLS_VER}
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
    rlRun "rm -r /etc/pki/ca-trust/source/anchors/server*"
    CleanupDo
    tcfCheckFinal
  rlPhaseEnd; }

  rlJournalPrintText
rlJournalEnd; }
