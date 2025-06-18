#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rsyslog/Sanity/imkafka-TLS-module-test
#   Description: sanity test for imkafka module with a fully configurable TLS setup.
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
PQC_SIG_ALG="ML-DSA-65"
# --- End Algorithm-Specific Parameters ---

rlJournalStart && {
  rlPhaseStartSetup && {
    rlRun "rlImport --all" 0 "Import libraries" || rlDie "cannot continue"

    # Check for PQC support if requested
    if [ "$KAFKA_CRYPTO_ALG" = "$PQC_SIG_ALG" ] || [ "$RSYSLOG_CRYPTO_ALG" = "$PQC_SIG_ALG" ]; then
        if ! openssl list -key-management-algorithms | grep -q -i "$PQC_SIG_ALG"; then
            rlSkip "Required PQC algorithm '$PQC_SIG_ALG' not supported. Skipping test."
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
    rlRun "rlFileBackup --clean /var/log/imkafka.log /tmp/kafka-logs /tmp/zookeeper"
    rlRun "rm -rf /var/log/imkafka.log /tmp/kafka-logs /tmp/zookeeper"

    # --- Certificate Generation ---
    KEY_PASSWORD="testpassword"
    STORE_PASSWORD="testpassword"
    FQDN="localhost"

    # Determine CA algorithm (use RSA in hybrid modes for Java compatibility)
    CA_ALG="RSA"
    if [ "$KAFKA_CRYPTO_ALG" = "$PQC_SIG_ALG" ] && [ "$RSYSLOG_CRYPTO_ALG" = "$PQC_SIG_ALG" ]; then
        CA_ALG="$PQC_SIG_ALG"
    fi

    # 1. Create Certificate Authority (CA)
    rlLog "Step 1: Creating $CA_ALG Certificate Authority (CA)"
    rsyslogGeneratePrivateKey "ca.key" "$CA_ALG"
    rsyslogCreateSelfSignedCa "ca.key" "ca.pem" "/CN=TestKafka-$CA_ALG-CA"

    # 2. Create Kafka Server Certificate & Keystore
    rlLog "Step 2: Creating Kafka Server $KAFKA_CRYPTO_ALG Certificate and Keystore"
    rsyslogGeneratePrivateKey "server.key.pem" "$KAFKA_CRYPTO_ALG"
    rsyslogCreateCsr "server.key.pem" "server.csr" "/CN=$FQDN"
    rsyslogSignCertificate "server.csr" "ca.pem" "ca.key" "server.pem"
    SERVER_PKCS12_PATH="$TmpDir/server.p12"
    SERVER_TRUSTSTORE_PATH="$TmpDir/kafka.server.truststore.jks"
    rlRun "openssl pkcs12 -export -in server.pem -inkey server.key.pem -certfile ca.pem -name $FQDN -out $SERVER_PKCS12_PATH -password pass:$STORE_PASSWORD"
    rlRun "keytool -keystore $SERVER_TRUSTSTORE_PATH -alias CARoot -importcert -file ca.pem -storepass $STORE_PASSWORD -noprompt"

    # 3. Create Kafka Console Producer Certificate & Keystore
    rlLog "Step 3: Creating Kafka Console Producer $KAFKA_CRYPTO_ALG Certificate and Keystore"
    rsyslogGeneratePrivateKey "producer-client.key.pem" "$KAFKA_CRYPTO_ALG"
    rsyslogCreateCsr "producer-client.key.pem" "producer-client.csr" "/CN=kafkaconsoleproducer"
    rsyslogSignCertificate "producer-client.csr" "ca.pem" "ca.key" "producer-client.pem"
    PRODUCER_PKCS12_PATH="$TmpDir/producer-client.p12"
    rlRun "openssl pkcs12 -export -in producer-client.pem -inkey producer-client.key.pem -certfile ca.pem -name kafkaconsoleproducer -out $PRODUCER_PKCS12_PATH -password pass:$STORE_PASSWORD"
    PRODUCER_TRUSTSTORE_PATH="$TmpDir/kafka.producer.truststore.jks"
    rlRun "keytool -keystore $PRODUCER_TRUSTSTORE_PATH -alias CARoot -importcert -file ca.pem -storepass $STORE_PASSWORD -noprompt"

    # 4. Create Rsyslog Client Certificate & Key
    rlLog "Step 4: Creating rsyslog Client $RSYSLOG_CRYPTO_ALG Certificate and Key"
    rsyslogGeneratePrivateKey "rsyslog.client.key.pem" "$RSYSLOG_CRYPTO_ALG"
    rsyslogCreateCsr "rsyslog.client.key.pem" "rsyslog.client.csr" "/CN=rsyslog-$RSYSLOG_CRYPTO_ALG-client"
    rsyslogSignCertificate "rsyslog.client.csr" "ca.pem" "ca.key" "rsyslog.client.pem"

    # Clean up intermediate CSR files
    rlRun "rm ./*.csr" 0 "Clean up all CSR files"

    # 5. Create Kafka producer properties file
    rlLog "Step 5: Creating SSL properties file for Kafka console producer"
    PRODUCER_SSL_PROPERTIES="$TmpDir/producer-ssl.properties"
    rlRun "cat > $PRODUCER_SSL_PROPERTIES <<EOF
security.protocol=SSL
ssl.truststore.location=$PRODUCER_TRUSTSTORE_PATH
ssl.truststore.password=$STORE_PASSWORD
ssl.keystore.type=PKCS12
ssl.keystore.location=$PRODUCER_PKCS12_PATH
ssl.keystore.password=$STORE_PASSWORD
ssl.key.password=$STORE_PASSWORD
EOF"

    # --- SELinux and Permissions Fix for Rsyslog ---
    rlLog "Step 6: Setting up a secure directory for rsyslog certificates"
    RSYSLOG_CERT_DIR="$TmpDir/rsyslog_certs"
    rlRun "mkdir -p $RSYSLOG_CERT_DIR"
    rlRun "cp ca.pem rsyslog.client.pem rsyslog.client.key.pem $RSYSLOG_CERT_DIR/"
    rlRun "chcon -t etc_t -R $RSYSLOG_CERT_DIR"

    # --- Kafka and Zookeeper Setup ---
    rlRun "wget https://archive.apache.org/dist/kafka/3.9.1/kafka_2.13-3.9.1.tgz"
    rlRun "tar -xzf kafka_2.13-3.9.1.tgz"
    rlRun "cd kafka_2.13-3.9.1"


    # Modify Kafka's server.properties for TLS
    KAFKA_SERVER_PROPERTIES="config/server.properties"
    rlFileBackup "$KAFKA_SERVER_PROPERTIES"
    rlLog "Modifying $KAFKA_SERVER_PROPERTIES for TLS..."
    rlRun "sed -i -e '/^listeners=/d' -e '/^advertised.listeners=/d' -e '/^security.protocol=/d' -e '/^ssl.client.auth=/d' -e '/^inter.broker.listener.name=/d' -e '/^ssl.keystore.location=/d' -e '/^ssl.keystore.type=/d' $KAFKA_SERVER_PROPERTIES"

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

    # Start Zookeeper and Kafka
    rlRun "bin/zookeeper-server-start.sh config/zookeeper.properties &"
    zookeeperPID=$!
    CleanupRegister "rlRun 'kill $zookeeperPID || true' 0 'kill zookeeper server'; rlWaitForSocket --close 2181"
    rlWaitForSocket 2181

    rlRun "bin/kafka-server-start.sh config/server.properties &"
    kafkaPID=$!
    CleanupRegister "rlRun 'kill $kafkaPID || true' 0 'kill kafka server'; rlWaitForSocket --close $KAFKA_PORT_TLS"
    rlWaitForSocket $KAFKA_PORT_TLS
    rlRun "sleep 15"

    rlLog "Creating Kafka topic 'test' using TLS..."
    rlRun "bin/kafka-topics.sh --create --bootstrap-server $FQDN:$KAFKA_PORT_TLS --command-config $PRODUCER_SSL_PROPERTIES --replication-factor 1 --partitions 1 --topic test" 0-255

    # Configure rsyslog with imkafka
    rlLog "Configuring rsyslog with imkafka for TLS"
    rsyslogPrepareConf
    rsyslogConfigAddTo RULES <<EOF
module(load="imkafka")

ruleset(name="imkafka_ruleset"){
  action(type="omfile" file="/var/log/imkafka.log")
}

input(type="imkafka"
      broker="$FQDN:$KAFKA_PORT_TLS"
      topic="test"
      ruleset="imkafka_ruleset"
      consumergroup="rsyslog-group"
      confParam=[ "security.protocol=ssl",
                  "ssl.ca.location=$RSYSLOG_CERT_DIR/ca.pem",
                  "ssl.certificate.location=$RSYSLOG_CERT_DIR/rsyslog.client.pem",
                  "ssl.key.location=$RSYSLOG_CERT_DIR/rsyslog.client.key.pem" ]
     )
EOF
    rsyslogServiceStart
  rlPhaseEnd; }

  tcfTry "Tests" --no-assert && {
    rlPhaseStartTest && {
      TEST_MESSAGE="imkafka-secure-test: kafka-producer($KAFKA_CRYPTO_ALG) -> rsyslog-consumer($RSYSLOG_CRYPTO_ALG)"
      rlLog "Sending message to Kafka: '$TEST_MESSAGE'"
      rlRun "echo '$TEST_MESSAGE' | bin/kafka-console-producer.sh --broker-list $FQDN:$KAFKA_PORT_TLS --topic test --producer.config $PRODUCER_SSL_PROPERTIES"

      rlLog "Waiting for rsyslog/imkafka to consume the message..."
      rlRun "sleep 15"

      rlLog "Checking for message in rsyslog output file (/var/log/imkafka.log)..."
      rlAssertGrep "$TEST_MESSAGE" /var/log/imkafka.log
    rlPhaseEnd; }
  tcfFin; }

  rlPhaseStartCleanup && {
    CleanupDo
    tcfCheckFinal
  rlPhaseEnd; }

  rlJournalPrintText
rlJournalEnd; }