#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rsyslog/Sanity/impstats-zabbix-lld
#   Description: Test impstats module Zabbix LLD output format (upstream PR #6154)
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
STATSFILE="/tmp/rsyslog-impstats-zabbix.log"
RSYSLOG_CONF="/etc/rsyslog.conf"
LOGFILE="/tmp/rsyslog-test.log"
RSYSLOG_PIDFILE="/tmp/rsyslog-test.pid"

rlJournalStart
    rlPhaseStartSetup
        rlImport --all
        rlAssertRpm "$PACKAGE"

        rlRun "rm -f \"$STATSFILE\" \"$LOGFILE\" \"$RSYSLOG_PIDFILE\"" 0 "Clean up any pre-existing test files"

        rlRun "rsyslogSetup" 0 "Initialize rsyslog test environment"

        rlRun "rsyslogServiceStop" 0 "Stopping system rsyslog service"
        rlRun "systemctl stop syslog.socket" 0 "Stop default syslog.socket"
        rlRun "systemctl disable syslog.socket" 0 "Disable default syslog.socket"

        rlRun "rsyslogPrepareConf" 0 "Prepare base rsyslog configuration"

        rsyslogConfigReplace MODULES <<EOF
module(load="imuxsock")
module(load="impstats"
    interval="1"
    format="zabbix"
    log.syslog="off"
    log.file="$STATSFILE")
EOF

        rsyslogConfigReplace RULES <<EOF
template(name="outfmt" type="string" string="%msg%\n")
:msg, regex, "msgnum:.*" action(type="omfile" file="$LOGFILE" template="outfmt")
EOF

        rlRun "rsyslogPrintEffectiveConfig -n" 0 "Printing effective rsyslog config"

        rlRun "rsyslogd -N1 -f \"$RSYSLOG_CONF\" | tee /tmp/rsyslog-check.log" 0 "Validating rsyslog config"

        rlRun "rsyslogd -n -f \"$RSYSLOG_CONF\" -i \"$RSYSLOG_PIDFILE\" &" 0 "Starting rsyslogd directly"
        RSYSLOGD_BG_PID=$!
        rlLog "rsyslogd background PID: $RSYSLOGD_BG_PID"

        rlRun "sleep 2" 0 "Waiting for rsyslog to initialize"
    rlPhaseEnd

    rlPhaseStartTest "Verify Zabbix LLD format output"
        rlLog "Sending test messages to generate stats"
        rlRun "logger -t impstats-zabbix-test 'test message for stats generation'" 0 "Sending test message"

        rlLog "Waiting for impstats to flush at least two intervals"
        rlRun "sleep 5"

        rlLog "Contents of stats file:"
        rlRun "cat \"$STATSFILE\""

        rlLog "Verifying stats file is not empty"
        rlAssertExists "$STATSFILE"
        rlRun "test -s \"$STATSFILE\"" 0 "Stats file is non-empty"

        rlLog "Verifying output is valid JSON (arrayed format)"
        rlRun "python3 -c \"
import json, sys
with open('$STATSFILE') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        print('Parsed JSON successfully:', type(data).__name__)
print('All lines are valid JSON')
\"" 0 "All stats lines are valid JSON"

        rlLog "Verifying Zabbix LLD format contains expected structure"
        rlRun "python3 -c \"
import json, sys
found_valid = False
with open('$STATSFILE') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        if isinstance(data, dict):
            found_valid = True
            print('Keys found:', list(data.keys()))
if not found_valid:
    print('ERROR: No valid Zabbix format entries found', file=sys.stderr)
    sys.exit(1)
print('Zabbix LLD format structure verified')
\"" 0 "Stats output follows Zabbix LLD JSON structure"

        rlLog "Verifying standard rsyslog stat origins appear in the output"
        rlRun "grep -q 'imuxsock' \"$STATSFILE\"" 0 "imuxsock stats present in Zabbix output"
    rlPhaseEnd

    rlPhaseStartTest "Verify legacy format is NOT produced"
        rlLog "Verifying the output does NOT contain legacy key=value format"
        rlRun "grep -q 'origin=' \"$STATSFILE\"" 1 "Legacy 'origin=' format should not appear in Zabbix mode"
    rlPhaseEnd

    rlPhaseStartCleanup
        local pid
        if [ -f "$RSYSLOG_PIDFILE" ] && pid=$(cat "$RSYSLOG_PIDFILE") && kill -0 "$pid" 2>/dev/null; then
            rlLog "Found running rsyslogd with PID $pid, attempting to stop it."
            rlRun "kill $pid" 0,1 "Stopping background rsyslogd"
            rlRun "wait $pid" 0,1,127 "Waiting for rsyslogd to exit"
        fi
        rlRun "rm -f \"$STATSFILE\" \"$LOGFILE\" \"$RSYSLOG_PIDFILE\"" 0 "Remove test files"
        rsyslogCleanup
    rlPhaseEnd
rlJournalEnd
