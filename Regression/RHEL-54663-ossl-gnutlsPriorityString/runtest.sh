#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Attila Lakatos <alakatos@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2024 Red Hat, Inc. All rights reserved.
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

. /usr/share/beakerlib/beakerlib.sh || exit 1
PACKAGE="rsyslog"
OUTPUT="/var/log/RHEL-54663"
HOST="localhost"
PORT="514"

setup_certificates() {
	rlRun "pushd /etc/rsyslog.d"
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
cn = "$(hostname)"
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
	rlRun "popd"
}

setup_config() {
	rsyslogConfigAppend "GLOBALS" <<EOF
global(
  DefaultNetstreamDriver="ossl"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/ca-cert.pem"
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/server-cert.pem"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/server-key.pem"
)
EOF

	rsyslogConfigAppend "RULES" /etc/rsyslog.conf <<EOF
module(
	load="imtcp"
	StreamDriver.Name="ossl"
	StreamDriver.Mode="1"
	StreamDriver.Authmode="anon"
	gnutlsPriorityString="Protocol=-ALL,TLSv1.2\nCipherString=ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-SHA384, ECDHE-RSA-AES256-SHA384, ECDHE-ECDSA-AES128-SHA256, ECDHE-RSA-AES128-SHA256, ECDH-ECDSA-AES256-GCM-SHA384, ECDH-ECDSA-AES128-GCM-SHA256, ECDH-ECDSA-AES128-SHA256, AES256-GCM-SHA384, AES128-GCM-SHA256, AES128-SHA256"
)

ruleset(name="myruleset"
	queue.type="fixedArray"
	queue.size="250000"
	queue.dequeueBatchSize="4096"
	queue.workerThreads="4"
	queue.workerThreadMinimumMessages="60000"
) {
	action(type="omfile" File="$OUTPUT"
			ioBufferSize="64k" flushOnTXEnd="off"
			asyncWriting="on")
}

input(type="imtcp" port="$PORT" ruleset="myruleset")
EOF
}

rlJournalStart
	rlPhaseStartSetup
		rlRun "rlImport --all" || rlDie 'cannot continue'
		CleanupRegister 'rlRun "rsyslogCleanup"'
		rlRun "rsyslogSetup"
		rsyslogPrepareConf
		rsyslogResetLogFilePointer /var/log/messages
		CleanupRegister 'rlRun "rsyslogServiceRestore"'
		CleanupRegister 'rlRun "rsyslogServiceStop"; rlRun "rlFileRestore"'
		rlRun "rlFileBackup --clean $OUTPUT"
		setup_certificates
		setup_config
		rlRun "rsyslogPrintEffectiveConfig -n"
		rlRun "rsyslogServiceStart && sleep 2"
		rlRun "rsyslogServiceStatus"
		rlRun "nmap --script +ssl-enum-ciphers -p $PORT $HOST"
	rlPhaseEnd

	# In certain versions of rsyslog, the gnutlsPriorityString(currently used for openssl) option is not respected.
	# Even though the value is set in the config, internally it can be broken. This test suite creates an rsyslog listener at port $PORT,
	# it will only accept TLSv1.2 ciphers, further restricted to some specific ones see above. First, we verify that no cipher from other TLS version
	# can be used to establish connection (TLS1, TLS1.1, TLS1.3). Lastly, we check if messages can be transmitted using TLS1.2.

	# Connecting with tls1, tls1_1 or tls1_3 should fail
	rlPhaseStartTest "Connect with tls1 ciphers" && {
		CIPHERS=$(openssl ciphers -v -s -tls1 | awk '{print $1}')
		for cipher in $CIPHERS; do
			echo "Processing cipher: $cipher"
			rlRun "echo 'Trying to connect with $cipher (should fail)' | openssl s_client -connect $HOST:$PORT -cipher $cipher" 1-255
		done
	rlPhaseEnd; }

	rlPhaseStartTest "Connect with tls1_1 ciphers" && {
		CIPHERS=$(openssl ciphers -v -s -tls1_1 | awk '{print $1}')
		for cipher in $CIPHERS; do
			echo "Processing cipher: $cipher"
			rlRun "echo 'Trying to connect with $cipher (should fail)' | openssl s_client -connect $HOST:$PORT -cipher $cipher" 1-255
		done
	rlPhaseEnd; }

	rlPhaseStartTest "Connect with tls1_3 ciphers" && {
		CIPHERS=$(openssl ciphers -v -s -tls1_3 | awk '{print $1}')
		for cipher in $CIPHERS; do
			echo "Processing cipher: $cipher"
			rlRun "echo 'Trying to connect with $cipher (should fail)' | openssl s_client -connect $HOST:$PORT -cipher $cipher" 1-255
		done
	rlPhaseEnd; }

	# Connecting with tls1_2 should succeed for particular ciphers listed in the config
	rlPhaseStartTest "Connect with tls1_2 ciphers" && {
		CIPHERS=(
			"ECDHE-RSA-AES128-SHA256"
			"ECDHE-RSA-AES128-GCM-SHA256"
			"ECDHE-RSA-AES256-SHA384"
			"AES128-SHA256"
			"AES128-GCM-SHA256"
			"AES256-GCM-SHA384"
		)
		for cipher in "${CIPHERS[@]}"; do
			echo "Processing cipher: $cipher"
			rlRun "echo 'Trying to connect with $cipher (should pass)' | openssl s_client -connect $HOST:$PORT -cipher $cipher" 0
		done

		sleep 3
		for cipher in "${CIPHERS[@]}"; do
			rlAssertGrep "Trying to connect with $cipher" $OUTPUT -E
		done

	rlPhaseEnd; }

	rlPhaseStartTest "Connect with extremely weak ciphers" && {
		CIPHERS=(
			"AECDH-DES-CBC3-SHA"
			"AECDH-AES128-SHA"
			"AECDH-AES256-SHA"
			"AECDH-RC4-SHA"
			"ECDHE-RSA-DES-CBC3-SHA"
		)
		for cipher in "${CIPHERS[@]}"; do
			echo "Processing cipher: $cipher"
			rlRun "echo 'Trying to connect with weak $cipher (should fail)' | openssl s_client -connect $HOST:$PORT -cipher $cipher" 1-255
		done
	rlPhaseEnd; }

	rlPhaseStartCleanup
		CleanupDo
	rlPhaseEnd
rlJournalPrintText
rlJournalEnd
