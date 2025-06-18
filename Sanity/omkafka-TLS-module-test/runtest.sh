#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rsyslog/Sanity/omkafka-TLS-module-test
#   Description: sanity test for omkafka module with a fully configurable TLS setup.
#   Author: Patrik Koncity <pkoncity@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Copyright (c) 2019, 2025 Red Hat, Inc.
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
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="rsyslog"

# --- Algorithm-Specific Parameters ---
# This variable can be set to "RSA" or a PQC algorithm like "ML-DSA-65"
# CRYPTO_ALGO="RSA"
PQC_SIG_ALGO="ML-DSA-65"
# --- End Algorithm-Specific Parameters ---

rlJournalStart && {
  rlPhaseStartSetup && {
    rlRun "rlImport --all" 0 "Import libraries" || rlDie "cannot continue"

    # Define the algorithm for OpenSSL, defaulting to RSA
    OPENSSL_ALG="${CRYPTO_ALGO:-RSA}"
    if [ "$CRYPTO_ALGO" = "ML-DSA-65" ]; then
        OPENSSL_ALG="$PQC_SIG_ALGO"
        # Check for crypto support before proceeding
        if ! openssl list -key-management-algorithms | grep -q -i "$OPENSSL_ALG"; then
            rlSkip "Required PQC algorithm '$OPENSSL_ALG' is NOT supported. Skipping test."
        fi
    fi

    CleanupRegister 'rlRun "rlSEPortRestore"'
    CleanupRegister 'rlRun "rsyslogCleanup"'
    rlRun "rsyslogSetup"

    KAFKA_PORT_TLS="9093"
    rlRun "rlSEPortAdd tcp $KAFKA_PORT_TLS syslogd_port_t"

    rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
    CleanupRegister "rlRun 'rm -rf \$TmpDir' 0 'Removing tmp directory'"
    CleanupRegister 'rlRun "popd"'
    rlRun "pushd \$TmpDir"

    CleanupRegister 'rlRun "rlFileRestore"'
    rlRun "rlFileBackup --clean /tmp/kafka-logs /tmp/zookeeper"
    rlRun "rm -rf /tmp/kafka-logs /tmp/zookeeper"

    # --- Certificate Generation using Library Functions ---
    STORE_PASSWORD="testpassword"
    FQDN="localhost"

    # 1. Create Certificate Authority (CA)
    rlLog "Step 1: Creating $CRYPTO_ALGO Certificate Authority (CA)"
    rsyslogGeneratePrivateKey "ca.key" "$OPENSSL_ALG"
    rsyslogCreateSelfSignedCa "ca.key" "ca.pem" "/CN=TestKafka-$CRYPTO_ALGO-CA"

    # 2. Create Kafka Server Certificate & Keystore
    rlLog "Step 2: Creating Kafka Server $CRYPTO_ALGO Certificate and Keystore"
    rsyslogGeneratePrivateKey "server.key.pem" "$OPENSSL_ALG"
    rsyslogCreateCsr "server.key.pem" "server.csr" "/CN=$FQDN"
    rsyslogSignCertificate "server.csr" "ca.pem" "ca.key" "server.pem"
    SERVER_PKCS12_PATH="$TmpDir/server.p12"
    SERVER_TRUSTSTORE_PATH="$TmpDir/kafka.server.truststore.jks"
    rlRun "openssl pkcs12 -export -in server.pem -inkey server.key.pem -certfile ca.pem -name $FQDN -out $SERVER_PKCS12_PATH -password pass:$STORE_PASSWORD"
    rlRun "keytool -keystore $SERVER_TRUSTSTORE_PATH -alias CARoot -importcert -file ca.pem -storepass $STORE_PASSWORD -noprompt"

    # 3. Create Kafka Client Tools Certificate & Keystore
    rlLog "Step 3: Creating Kafka Client Tools $CRYPTO_ALGO Certificate and Keystore"
    rsyslogGeneratePrivateKey "client-tools.key.pem" "$OPENSSL_ALG"
    rsyslogCreateCsr "client-tools.key.pem" "client-tools.csr" "/CN=kafkatoolsclient"
    rsyslogSignCertificate "client-tools.csr" "ca.pem" "ca.key" "client-tools.pem"
    CLIENT_PKCS12_PATH="$TmpDir/client-tools.p12"
    rlRun "openssl pkcs12 -export -in client-tools.pem -inkey client-tools.key.pem -certfile ca.pem -name kafkatoolsclient -out $CLIENT_PKCS12_PATH -password pass:$STORE_PASSWORD"
    CLIENT_TOOLS_TRUSTSTORE_PATH="$TmpDir/kafka.client-tools.truststore.jks"
    rlRun "keytool -keystore $CLIENT_TOOLS_TRUSTSTORE_PATH -alias CARoot -importcert -file ca.pem -storepass $STORE_PASSWORD -noprompt"

    # 4. Create Rsyslog Client Certificate & Key
    rlLog "Step 4: Creating rsyslog Client $CRYPTO_ALGO Certificate and Key"
    rsyslogGeneratePrivateKey "rsyslog.client.key.pem" "$OPENSSL_ALG"
    rsyslogCreateCsr "rsyslog.client.key.pem" "rsyslog.client.csr" "/CN=rsyslog-$CRYPTO_ALGO-client"
    rsyslogSignCertificate "rsyslog.client.csr" "ca.pem" "ca.key" "rsyslog.client.pem"
    # Clean up all intermediate CSR files
    rlRun "rm ./*.csr" 0 "Clean up CSR files"

    # 5. Create Kafka client properties file
    rlLog "Step 5: Creating SSL properties file for Kafka client tools ($CRYPTO_ALGO)"
    CLIENT_SSL_PROPERTIES="$TmpDir/client-ssl.properties"
    rlRun "cat > $CLIENT_SSL_PROPERTIES <<EOF
security.protocol=SSL
ssl.truststore.location=$CLIENT_TOOLS_TRUSTSTORE_PATH
ssl.truststore.password=$STORE_PASSWORD
ssl.keystore.type=PKCS12
ssl.keystore.location=$CLIENT_PKCS12_PATH
ssl.keystore.password=$STORE_PASSWORD
ssl.key.password=$STORE_PASSWORD
EOF"

    # --- SELinux and Permissions Fix for Rsyslog ---
    rlLog "Step 6: Setting up a secure directory for rsyslog certificates"
    RSYSLOG_CERT_DIR="$TmpDir/rsyslog_certs"
    rlRun "mkdir -p $RSYSLOG_CERT_DIR"
    rlRun "cp ca.pem rsyslog.client.pem rsyslog.client.key.pem $RSYSLOG_CERT_DIR/"
    rlRun "chcon -t etc_t -R $RSYSLOG_CERT_DIR"

    # --- Kafka Setup ---
    rlRun "wget https://archive.apache.org/dist/kafka/3.9.1/kafka_2.13-3.9.1.tgz"
    rlRun "tar -xzf kafka_2.13-3.9.1.tgz"
    rlRun "cd kafka_2.13-3.9.1"

    KAFKA_SERVER_PROPERTIES="config/server.properties"
    rlFileBackup "$KAFKA_SERVER_PROPERTIES"
    rlLog "Modifying $KAFKA_SERVER_PROPERTIES for TLS..."
    rlRun "sed -i -e '/^listeners=/d' -e '/^advertised.listeners=/d' -e '/^security.protocol=/d' -e '/^ssl.client.auth=/d' -e '/^inter.broker.listener.name=/d' -e '/^ssl.keystore.location=/d' -e '/^ssl.keystore.type=/d' $KAFKA_SERVER_PROPERTIES"

    # Kafka is Java-based, so PKCS12 is more reliable for non-RSA keys.
    rlRun "cat >> $KAFKA_SERVER_PROPERTIES <<EOF

# TLS settings added by test script
listeners=SSL://$FQDN:$KAFKA_PORT_TLS
advertised.listeners=SSL://$FQDN:$KAFKA_PORT_TLS
inter.broker.listener.name=SSL
security.protocol=SSL
ssl.keystore.type=PKCS12
ssl.keystore.location=$SERVER_PKCS12_PATH
ssl.keystore.password=$STORE_PASSWORD
ssl.key.password=$STORE_PASSWORD
ssl.truststore.location=$SERVER_TRUSTSTORE_PATH
ssl.truststore.password=$STORE_PASSWORD
ssl.client.auth=required
EOF"

    rlRun "bin/zookeeper-server-start.sh config/zookeeper.properties &"
    zookeeperPID=$!
    CleanupRegister "rlRun 'kill $zookeeperPID || true' 0 'kill zookeeper server'; rlWaitForSocket --close 2181"
    rlWaitForSocket 2181

    rlRun "bin/kafka-server-start.sh config/server.properties &"
    kafkaPID=$!
    CleanupRegister "rlRun 'kill $kafkaPID || true' 0 'kill kafka server'; rlWaitForSocket --close $KAFKA_PORT_TLS"
    rlWaitForSocket $KAFKA_PORT_TLS

    CleanupRegister "rlRun 'pkill -f \"kafka.tools.ConsoleConsumer\" || true' 0 'Force kill any remaining Kafka ConsoleConsumer'"
    rlRun "sleep 15" 0 "Giving Kafka time to fully initialize"

    rlLog "Creating Kafka topic 'test' using TLS..."
    rlRun "bin/kafka-topics.sh --create --bootstrap-server $FQDN:$KAFKA_PORT_TLS --command-config $CLIENT_SSL_PROPERTIES --replication-factor 1 --partitions 1 --topic test" 0-255

    # Configure rsyslog omkafka
    rlLog "Configuring rsyslog omkafka for TLS using $CRYPTO_ALGO certs"
    rsyslogPrepareConf
    rsyslogConfigAddTo RULES <<EOF
module(load="omkafka")
template(name="ForwardFormat" type="string" string="%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\\n")
local2.* action(type="omkafka"
                broker="$FQDN:$KAFKA_PORT_TLS"
                topic="test"
                template="ForwardFormat"
                confParam=[ "security.protocol=ssl",
                            "ssl.ca.location=$RSYSLOG_CERT_DIR/ca.pem",
                            "ssl.certificate.location=$RSYSLOG_CERT_DIR/rsyslog.client.pem",
                            "ssl.key.location=$RSYSLOG_CERT_DIR/rsyslog.client.key.pem"  ]
               )
EOF
    rsyslogServiceStart
  rlPhaseEnd; }

  rlPhaseStartTest && {
    TEST_MESSAGE="secure rsyslog test message via Kafka TLS with $CRYPTO_ALGO client"
    rlLog "Starting Kafka console consumer with TLS ($CRYPTO_ALGO client cert)..."
    rlRun "bin/kafka-console-consumer.sh --bootstrap-server $FQDN:$KAFKA_PORT_TLS --topic test --consumer.config $CLIENT_SSL_PROPERTIES --from-beginning > out.consumer 2>&1 &" 0-255
    consumerPID=$!

    rlRun "sleep 15" 0 "Waiting for consumer to connect"

    rlLog "Sending message to rsyslog: '$TEST_MESSAGE'"
    rlRun "logger -p local2.info '$TEST_MESSAGE'"
    rlRun "sleep 15" 0 "Waiting for message to propagate"

    rlLog "Stopping Kafka console consumer (PID: $consumerPID)..."
    rlRun "kill -SIGINT $consumerPID || true" 0

    rlLog "Waiting up to 20s for consumer to terminate gracefully..."
    for i in {1..20}; do
        if ! kill -0 $consumerPID 2>/dev/null; then
            rlLog "Consumer process $consumerPID terminated."
            consumerPID=""
            break
        fi
        sleep 1
    done

    if [ -n "$consumerPID" ]; then
        rlLog "Consumer did not terminate gracefully after 20s. Forcing kill."
        rlRun "kill -9 $consumerPID"
    fi

    rlLog "Checking for message in consumer output file (out.consumer)..."
    rlAssertGrep "$TEST_MESSAGE" out.consumer
  rlPhaseEnd; }

  rlPhaseStartCleanup && {
    CleanupDo
    tcfCheckFinal
  rlPhaseEnd; }

  rlJournalPrintText
rlJournalEnd; }