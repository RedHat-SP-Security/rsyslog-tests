#!/bin/bash
. /usr/share/beakerlib/beakerlib.sh || exit 1

rlJournalStart
    rlPhaseStartSetup "Setup"
        rlAssertRpm "rsyslog" "rsyslog-gnutls" "openssl"
        rlRun "rlImport openssl/certgen"

        # Stop rsyslog to apply new configuration
        rlServiceStop rsyslog.service

        # Backup original configuration
        rlFileBackup "/etc/rsyslog.conf"
        rlFileBackup --clean "/etc/rsyslog.d"

        # Create a temporary directory for certificates
        rlRun "TmpDir=\$(mktemp -d)" 0 "Create tmp directory"
        rlRun "pushd \$TmpDir"

        # Generate CA, server, and client certificates
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509KeyGen client"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca server"
        rlRun "x509CertSign --CA ca client"

        # Create a Certificate Revocation List (CRL)
        rlRun "openssl ca -gencrl -config ca/ca.cnf -out crl.pem -keyfile ca/key.pem -cert ca/cert.pem" "Generate initial CRL"

        # Copy certificates to rsyslog.d
        rlRun "cp \$(x509Cert ca) /etc/rsyslog.d/ca.pem"
        rlRun "cp \$(x509Cert server) /etc/rsyslog.d/server-cert.pem"
        rlRun "cp \$(x509Key server) /etc/rsyslog.d/server-key.pem"
        rlRun "cp crl.pem /etc/rsyslog.d/crl.pem"

        # Configure rsyslog server (imtcp with gtls)
        cat > /etc/rsyslog.d/imtcp.conf <<EOF
module(load="imtcp")
input(type="imtcp" port="6514"
      streamdriver.name="gtls"
      streamdriver.mode="1"
      streamdriver.authmode="x509/certvalid"
      defaultnetstreamdrivercafile="/etc/rsyslog.d/ca.pem"
      defaultnetstreamdrivercrlfile="/etc/rsyslog.d/crl.pem"
      defaultnetstreamdrivercertfile="/etc/rsyslog.d/server-cert.pem"
      defaultnetstreamdriverkeyfile="/etc/rsyslog.d/server-key.pem"
)
EOF
        # Configure rsyslog client (omfwd with gtls)
        cat > /etc/rsyslog.conf <<EOF
global(defaultNetstreamDriver="gtls"
       defaultNetstreamDriverCAFile="/etc/rsyslog.d/ca.pem"
       defaultNetstreamDriverCertFile="\$(x509Cert client)"
       defaultNetstreamDriverKeyFile="\$(x509Key client)")

action(type="omfwd" protocol="tcp" target="127.0.0.1" port="6514"
       streamDriver="gtls" streamDriverMode="1"
       streamDriverAuthMode="x509/name"
       streamDriverPermittedPeers="localhost")

# For debugging
global(debug.logFile="/var/log/rsyslog-debug.log"
       debug.gnutls="1")
EOF
        rlRun "cat /etc/rsyslog.d/imtcp.conf"
        rlRun "cat /etc/rsyslog.conf"
    rlPhaseEnd

    rlPhaseStartTest "Test with valid CRL"
        # Ensure CRL is valid (just generated)
        rlRun "openssl crl -in /etc/rsyslog.d/crl.pem -noout -nextupdate"
        rlServiceStart rsyslog.service
        rlAssertGrep "rsyslogd was started" "/var/log/messages" -E
        # Send a test message
        rlRun "logger 'Message with valid CRL'"
        sleep 2
        # Check if the message was received
        rlAssertGrep "Message with valid CRL" "/var/log/messages"
        rlServiceStop rsyslog.service
    rlPhaseEnd

    rlPhaseStartTest "Test with expired CRL"
        # Create an expired CRL by setting the 'days' option to a negative value
        rlRun "openssl ca -gencrl -config ca/ca.cnf -out /etc/rsyslog.d/crl.pem -keyfile ca/key.pem -cert ca/cert.pem -days -1" "Generate expired CRL"
        rlRun "openssl crl -in /etc/rsyslog.d/crl.pem -noout -nextupdate"
        rlAssertGrep "nextUpdate" "$(rlRun 'openssl crl -in /etc/rsyslog.d/crl.pem -noout -nextupdate')"
        
        # Start rsyslog and expect it to fail to accept connections
        rlServiceStart rsyslog.service
        # The service should start, but not accept connections
        rlAssertGrep "rsyslogd was started" "/var/log/messages" -E

        # Try to send a message, it should fail
        rlRun "logger 'Message with expired CRL'"
        sleep 2
        # The message should NOT be in the log
        rlAssertNotGrep "Message with expired CRL" "/var/log/messages"
        # Check debug log for connection rejection
        rlAssertGrep "CRL in 'crl.pem' has expired" "/var/log/rsyslog-debug.log"
    rlPhaseEnd

    rlPhaseStartCleanup "Cleanup"
        rlServiceStop rsyslog.service
        rlFileRestore
        rlRun "popd"
        rlRun "rm -rf \$TmpDir"
        rlServiceRestore rsyslog.service
    rlPhaseEnd
rlJournalEnd
