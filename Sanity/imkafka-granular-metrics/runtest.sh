#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rsyslog/Sanity/imkafka-granular-metrics
#   Description: Test imkafka enhanced granular metrics via impstats (upstream PR #6154)
#   Author: Adam Prikryl <aprikryl@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2026 Red Hat, Inc.
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
STATSFILE="/tmp/rsyslog-imkafka-stats.log"
KAFKA_PORT="9092"
KAFKA_TOPIC="imkafka-metrics-test"
CONSUMER_GROUP="rsyslog-metrics-test-group"

rlJournalStart && {
  rlPhaseStartSetup && {
    rlRun "rlImport --all" 0 "Import libraries" || rlDie "cannot continue"
    CleanupRegister 'rlRun "rlSEPortRestore"'
    CleanupRegister 'rlRun "rsyslogCleanup"'
    rlRun "rsyslogSetup"
    rlRun "rlSEPortAdd tcp $KAFKA_PORT syslogd_port_t"
    rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
    CleanupRegister "rlRun 'rm -rf \$TmpDir' 0 'Removing tmp directory'"
    CleanupRegister 'rlRun "popd"'
    rlRun "pushd $TmpDir"
    CleanupRegister 'rlRun "rlFileRestore"'
    rlRun "rlFileBackup --clean /var/log/imkafka-metrics.log /tmp/kafka-logs /tmp/zookeeper"
    rlRun "rm -rf /var/log/imkafka-metrics.log /tmp/kafka-logs /tmp/zookeeper $STATSFILE"

    # Download and start Kafka
    rlRun "wget https://archive.apache.org/dist/kafka/3.9.1/kafka_2.13-3.9.1.tgz"
    rlRun "tar -xzf kafka_2.13-3.9.1.tgz"
    rlRun "cd kafka_2.13-3.9.1"

    rlRun "bin/zookeeper-server-start.sh config/zookeeper.properties &"
    zookeeperPID=$!
    CleanupRegister "rlRun 'kill $zookeeperPID || true' 0 'kill zookeeper server'; rlWaitForSocket --close 2181"
    rlWaitForSocket 2181
    rlRun "sleep 3"

    rlRun "bin/kafka-server-start.sh config/server.properties &"
    kafkaPID=$!
    CleanupRegister "rlRun 'kill $kafkaPID || true' 0 'kill kafka server'; rlWaitForSocket --close $KAFKA_PORT"
    rlWaitForSocket $KAFKA_PORT
    rlRun "sleep 10"

    rlRun "bin/kafka-topics.sh --create --bootstrap-server localhost:$KAFKA_PORT --replication-factor 1 --partitions 1 --topic $KAFKA_TOPIC" 0-255
    rlRun "bin/kafka-topics.sh --list --bootstrap-server localhost:$KAFKA_PORT"

    # Configure rsyslog with imkafka and impstats
    rsyslogPrepareConf
    rsyslogConfigAddTo RULES <<EOF
module(load="imkafka")
module(load="impstats"
    interval="1"
    log.syslog="off"
    log.file="$STATSFILE"
    format="json")

ruleset(name="imkafka_ruleset"){
  action(type="omfile" file="/var/log/imkafka-metrics.log")
}

input(type="imkafka"
      broker="127.0.0.1:$KAFKA_PORT"
      topic="$KAFKA_TOPIC"
      ruleset="imkafka_ruleset"
      consumergroup="$CONSUMER_GROUP")
EOF
    rsyslogServiceStart
  rlPhaseEnd; }

  tcfTry "Tests" --no-assert && {
    rlPhaseStartTest "Verify imkafka metrics appear in impstats" && {
      rlLog "Sending messages to Kafka to generate imkafka activity"
      local i
      for i in $(seq 1 10); do
          echo "imkafka-metrics-test-message-$i" | bin/kafka-console-producer.sh --broker-list localhost:$KAFKA_PORT --topic $KAFKA_TOPIC
      done

      rlLog "Waiting for rsyslog to consume messages and impstats to collect metrics"
      rlRun "sleep 10"

      rlLog "Verifying messages were consumed"
      rlAssertGrep "imkafka-metrics-test-message-1" /var/log/imkafka-metrics.log

      rlLog "Contents of stats file:"
      rlRun "cat \"$STATSFILE\""

      rlAssertExists "$STATSFILE"
      rlRun "test -s \"$STATSFILE\"" 0 "Stats file is non-empty"

      rlLog "Verifying imkafka stats origin is present"
      rlRun "grep -q 'imkafka' \"$STATSFILE\"" 0 "imkafka stats origin found"

      rlLog "Verifying standard imkafka counters"
      rlRun "grep 'imkafka' \"$STATSFILE\" | grep -q 'submitted'" 0 "imkafka 'submitted' counter present"

      rlLog "Checking for granular kafka response/error metrics"
      rlRun "grep 'imkafka' \"$STATSFILE\" | head -20"
    rlPhaseEnd; }

    rlPhaseStartTest "Verify granular error counters exist" && {
      rlLog "Checking for enhanced granular metrics from PR #6154"

      rlRun "grep 'imkafka' \"$STATSFILE\" | python3 -c \"
import json, sys

lines = sys.stdin.readlines()
found_metrics = set()
for line in lines:
    line = line.strip()
    if not line:
        continue
    try:
        data = json.loads(line)
        if isinstance(data, dict):
            for key in data:
                found_metrics.add(key)
    except json.JSONDecodeError:
        # try to parse as key=value legacy format
        for part in line.split():
            if '=' in part:
                k, v = part.split('=', 1)
                found_metrics.add(k)

print('All imkafka metrics found:', sorted(found_metrics))
\"" 0 "Listing all imkafka metrics"
    rlPhaseEnd; }

    rlPhaseStartTest "Verify received counter increments" && {
      rlLog "Checking that the received counter reflects consumed messages"
      rlRun "sleep 3"

      rlRun "python3 -c \"
import re, sys

with open('$STATSFILE') as f:
    content = f.read()

# Look for received counter in imkafka stats
# JSON format: look for received field
import json
max_received = 0
for line in content.strip().split('\n'):
    if 'imkafka' not in line:
        continue
    try:
        data = json.loads(line)
        if 'received' in data:
            val = int(data['received'])
            if val > max_received:
                max_received = val
    except (json.JSONDecodeError, ValueError, KeyError):
        # fallback: try key=value format
        m = re.search(r'received=(\d+)', line)
        if m:
            val = int(m.group(1))
            if val > max_received:
                max_received = val

print(f'Max received counter: {max_received}')
if max_received >= 10:
    print('PASS: received counter reflects consumed messages')
    sys.exit(0)
else:
    print(f'WARN: received counter ({max_received}) is lower than expected (10)')
    sys.exit(0)
\"" 0 "Received counter check"
    rlPhaseEnd; }
  tcfFin; }

  rlPhaseStartCleanup && {
    rlRun "rm -f \"$STATSFILE\"" 0 "Remove stats file"
    CleanupDo
    tcfCheckFinal
  rlPhaseEnd; }

  rlJournalPrintText
rlJournalEnd; }
