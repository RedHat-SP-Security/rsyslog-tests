#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rsyslog/Sanity/elasticsearch-TLS
#   Description: Smoke test for elastic search feature with configurable TLS
#   Author: Patrik Koncity <pkoncity@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2025 Red Hat, Inc.
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

# --- PQC Algorithm Details ---
# Using ML-DSA-65 (which corresponds to Dilithium3) for the PQC option.
PQC_SIG_ALG="ML-DSA-65"


rlJournalStart && {
  rlPhaseStartSetup && {
    rlRun "rlImport --all" 0 "Import libraries" || rlDie "cannot continue"

    # --- Install required packages ---
    rlRun "rpm -q openssl >/dev/null 2>&1 || yum install -y openssl" 0 "Ensure openssl is installed"
    # Install rsyslog-elasticsearch plugin
    ES_PLUGIN="$(rsyslogTranslate 'rsyslog-elasticsearch')"
    rlRun "rpm -q $ES_PLUGIN >/dev/null 2>&1 || yum install -y $ES_PLUGIN" 0 "Ensure rsyslog-elasticsearch plugin is installed"

    # --- Setup Elasticsearch Repository ---
    rlLog "Adding Elasticsearch Yum repository"
    rlRun "rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch" 0 "Import Elasticsearch GPG key"
    # Using a 7.x version for broad compatibility
    cat > /etc/yum.repos.d/elasticsearch.repo <<EOF
[elasticsearch-7.x]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
    rlRun "cat /etc/yum.repos.d/elasticsearch.repo" 0 "Show Elasticsearch repo file"
    rlRun "yum makecache" 0 "Update yum cache"

    # Install Elasticsearch and Java
    rlRun "yum install -y java-openjdk elasticsearch" 0 "Install Java and Elasticsearch"

    CleanupRegister 'tcfRun "rsyslogCleanup"'
    tcfRun "rsyslogSetup"
    rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
    CleanupRegister "rlRun 'rm -r \$TmpDir' 0 'Removing tmp directory'"
    CleanupRegister 'rlRun "popd"'
    rlRun "pushd \$TmpDir"

    # --- Certificate Generation ---
    rlLog "Generating TLS certificates using $CRYPTO_ALG algorithm"

    # Set the algorithm name for OpenSSL; default to RSA if CRYPTO_ALG is not set
    OPENSSL_ALG="${CRYPTO_ALG:-RSA}"
    [ "$CRYPTO_ALG" = "ML-DSA-65" ] && OPENSSL_ALG="$PQC_SIG_ALG"
    # Check for PQC support if selected
    if [ "$CRYPTO_ALG" = "ML-DSA-65" ]; then
         if ! openssl list -signature-algorithms | grep -q "$PQC_SIG_ALG"; then
            rlSkip "Skip: $PQC_SIG_ALG not supported by this version of OpenSSL"
            rlPhaseEnd; rlJournalEnd; exit 0
         fi
    fi

    # Generate all private keys using the library function
    rsyslogGeneratePrivateKey "ca.key" "$OPENSSL_ALG"
    rsyslogGeneratePrivateKey "server.key" "$OPENSSL_ALG"
    rsyslogGeneratePrivateKey "client.key" "$OPENSSL_ALG"

    # Create OpenSSL config with SANs
    SERVER_IP=$(hostname -I | awk '{print $1}')
    rsyslogCreateSanConfig "openssl.cnf" "localhost" "127.0.0.1,$SERVER_IP"

    # Create and sign certificates using the library functions
    rsyslogCreateSelfSignedCa "ca.key" "ca.crt" "/CN=MyTestCA"

    # Server certificate with SAN
    # The subject is taken from the config, so we pass a dummy one here.
    rsyslogCreateCsr "server.key" "server.csr" "/CN=localhost"
    rsyslogSignCertificate "server.csr" "ca.crt" "ca.key" "server.crt" 365 "openssl.cnf" "v3_req"

    # Client certificate (no SAN needed)
    rsyslogCreateCsr "client.key" "client.csr" "/CN=rsyslog-client"
    rsyslogSignCertificate "client.csr" "ca.crt" "ca.key" "client.crt"

    rlRun "rm ./*.csr" 0 "Clean up intermediate CSR files"
    # --- Configure Elasticsearch for TLS ---
    rlLog "Configuring Elasticsearch to use TLS"
    
    # Backup the original elasticsearch.yml and register its restoration for cleanup
    rlFileBackup /etc/elasticsearch/elasticsearch.yml
    CleanupRegister "rlFileRestore /etc/elasticsearch/elasticsearch.yml"
    
    rlRun "mkdir -p /etc/elasticsearch/certs"
    rlRun "cp server.crt server.key ca.crt /etc/elasticsearch/certs/"
    rlRun "chown -R elasticsearch:elasticsearch /etc/elasticsearch/certs/"

    # Append the discovery and TLS configuration block
    cat >> /etc/elasticsearch/elasticsearch.yml <<EOF

# --- Basic Cluster and TLS/SSL Configuration ---
network.host: 0.0.0.0
discovery.type: single-node
xpack.security.enabled: true

# Configure HTTP layer TLS
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.key: /etc/elasticsearch/certs/server.key
xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/server.crt
xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca.crt" ]
xpack.security.http.ssl.client_authentication: optional

# Configure Transport layer TLS (required for a secure cluster to start)
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.key: /etc/elasticsearch/certs/server.key
xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/server.crt
xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca.crt" ]
EOF

    # --- Bootstrap the 'elastic' user password BEFORE starting the service ---
    rlLog "Bootstrapping elastic user password"
    ELASTIC_PASSWORD=$(openssl rand -base64 16)
    rlLog "Generated temporary elastic password"
    echo "$ELASTIC_PASSWORD" | /usr/share/elasticsearch/bin/elasticsearch-keystore add bootstrap.password -x -f
    rlRun "/usr/share/elasticsearch/bin/elasticsearch-keystore list"

    CleanupRegister 'rlRun "rlSEBooleanRestore allow_ypbind"'
    rlRun "rlSEBooleanOn allow_ypbind"
    CleanupRegister 'rlRun "rlServiceStop elasticsearch"'
    rlRun "rlServiceStart elasticsearch"
    rlRun "rlWaitForSocket 9200 -t 90" 0 "Wait longer for secure Elasticsearch to start"
    
    CURL_TLS_OPTS_NO_CLIENT_CERT="--cacert $TmpDir/ca.crt"
    # Health check loop to ensure Elasticsearch API is fully responsive
    rlLog "Waiting for Elasticsearch cluster to be healthy..."
    ATTEMPTS=0
    MAX_ATTEMPTS=30
    until [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; do
        # We now have a password, so we expect a 200 OK
        curl --fail --silent $CURL_TLS_OPTS_NO_CLIENT_CERT -u elastic:$ELASTIC_PASSWORD -XGET 'https://127.0.0.1:9200/_cluster/health' | grep -q -E '"status":"(green|yellow)"'
        if [ $? -eq 0 ]; then
            rlLog "Elasticsearch cluster is healthy."
            break
        fi
        ATTEMPTS=$((ATTEMPTS+1))
        rlLog "Waiting for Elasticsearch health... (attempt $ATTEMPTS/$MAX_ATTEMPTS)"
        sleep 2
    done

    if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
        rlDie "Elasticsearch cluster did not become healthy in time."
    fi

    # Final status check
    rlRun "rlServiceStatus elasticsearch"

    # --- Test Elasticsearch TLS Connection ---
    CURL_TLS_OPTS="--cacert $TmpDir/ca.crt --cert $TmpDir/client.crt --key $TmpDir/client.key"
    rlRun "curl $CURL_TLS_OPTS -u elastic:$ELASTIC_PASSWORD -XGET 'https://127.0.0.1:9200/'" 0 "Verify Elasticsearch is up on HTTPS"

    # --- Configure Rsyslog for TLS ---
    rlLog "Configuring rsyslog to use omelasticsearch with TLS"
    
    # Create a directory for rsyslog certs and set permissions
    rlRun "mkdir -p /etc/rsyslog.d/pki"
    rlRun "cp $TmpDir/ca.crt /etc/rsyslog.d/pki/ca.crt"
    rlRun "chmod 644 /etc/rsyslog.d/pki/ca.crt" 0 "Set CA cert permissions for rsyslog"
    
    ESv=${ESv:+esVersion.major=\"$ESv\"}
    SearchIndex=${SearchIndex:+searchindex=\"$SearchIndex\" searchtype=\"\"}
    if [[ "$elasticBulkmode" == "on" ]]; then
      elasticBulkmode='bulkmode="on"'
    elif [[ "$elasticBulkmode" == "off" ]]; then
      elasticBulkmode='bulkmode="off"'
    else
      elasticBulkmode=''
    fi

    # Construct the omelasticsearch action with TLS parameters and credentials
    OMES_ACTION="action(type=\"omelasticsearch\" \
        server=\"127.0.0.1\" \
        usehttps=\"on\" \
        uid=\"elastic\" \
        pwd=\"$ELASTIC_PASSWORD\" \
        tls.cacert=\"/etc/rsyslog.d/pki/ca.crt\" \
        template=\"plain-syslog-tpl\" \
        $SearchIndex $ESv $elasticBulkmode)"

    rsyslogConfigAddTo "RULES" /etc/rsyslog.conf <<EOF
module(load="omelasticsearch") #for indexing to Elasticsearch

template(name="plain-syslog-tpl" type="list") {
    constant(value="{")
    constant(value="\"@timestamp\":\"")      property(name="timereported" dateFormat="rfc3339")
    constant(value="\",\"host\":\"")          property(name="hostname")
    constant(value="\",\"severity\":\"")      property(name="syslogseverity-text")
    constant(value="\",\"facility\":\"")      property(name="syslogfacility-text")
    constant(value="\",\"tag\":\"")         property(name="syslogtag" format="json")
    constant(value="\",\"message\":\"")       property(name="msg" format="json")
    constant(value="\"}")
}
$OMES_ACTION
EOF
    CleanupRegister 'rlRun "rlServiceStop rsyslog"'
    rlRun "rsyslogPrintEffectiveConfig -n"
    rlRun "rlServiceStart rsyslog"
    rlRun "netstat -putna | grep 9200" 0-255; :
  rlPhaseEnd; }

  tcfTry "Tests" --no-assert && {
    rlPhaseStartTest && {
      rlRun "logger testMSG"
      # Increase sleep time to allow for potential TLS handshake delays and async processing
      rlRun "sleep 30"
      rlRun -s "curl $CURL_TLS_OPTS -u elastic:$ELASTIC_PASSWORD -XGET 'https://127.0.0.1:9200/_all/_search?q=testMSG&pretty'"
      rlAssertGrep '"message" *: *"testMSG"' $rlRun_LOG
      rm -f $rlRun_LOG
    rlPhaseEnd; }
  tcfFin; }

  rlPhaseStartCleanup && {
    CleanupDo
    tcfCheckFinal
  rlPhaseEnd; }

rlJournalPrintText
rlJournalEnd; }