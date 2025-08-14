#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rsyslog/Sanity/impstats-dropped-messages
#   Description: Smoke test for counter of discarded messages in impstats module
#   Author: Adam Prikryl <aprikryl@redhat.com>
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

PACKAGE="rsyslog"
SOCKET="/tmp/rsyslog-test.sock"
STATSFILE="/tmp/rsyslog.stats"
RSYSLOG_CONF="/etc/rsyslog.conf"
LOGFILE="/tmp/rsyslog-test.log"
RSYSLOG_PIDFILE="/tmp/rsyslog-test.pid"

rlJournalStart
    rlPhaseStartSetup
        rlImport --all
        rlAssertRpm "$PACKAGE"

        rlRun "rm -f \"$SOCKET\" \"$STATSFILE\" \"$LOGFILE\" \"$RSYSLOG_PIDFILE\"" 0 "Clean up any pre-existing test files"

        rlRun "rsyslogSetup" 0 "Initialize rsyslog test environment"

        rlRun "rsyslogServiceStop" 0 "Stopping system rsyslog service"
        rlRun "systemctl stop syslog.socket" 0 "Stop default syslog.socket"
        rlRun "systemctl disable syslog.socket" 0 "Disable default syslog.socket"

        rlRun "rsyslogPrepareConf" 0 "Prepare base rsyslog configuration"

        rsyslogConfigReplace MODULES <<EOF
module(load="imuxsock")
input(type="imuxsock" Socket="$SOCKET" CreatePath="on"
      RateLimit.Interval="1" RateLimit.Burst="750")
module(load="impstats" log.file="$STATSFILE" interval="1" ruleset="stats" log.syslog="off")
EOF

        rsyslogConfigReplace RULES <<EOF
template(name="outfmt" type="string" string="%msg%\\n")

ruleset(name="stats") {
    stop # Discard stats messages after processing by impstats
}

# Using property filter syntax for regex matching
:msg, regex, "msgnum:.*" action(type="omfile" file="$LOGFILE" template="outfmt")
EOF

        rlRun "rsyslogPrintEffectiveConfig -n" 0 "Printing effective rsyslog config (grep non-commented lines)"

        rlRun "rsyslogd -N1 -f \"$RSYSLOG_CONF\" | tee /tmp/rsyslog-check.log" 0 "Validating rsyslog config"
        rlAssertExists "/tmp/rsyslog-check.log"

        rlRun "rsyslogd -n -f \"$RSYSLOG_CONF\" -i \"$RSYSLOG_PIDFILE\" &" 0 "Starting rsyslogd directly"
        RSYSLOGD_BG_PID=$!
        rlLog "rsyslogd background PID: $RSYSLOGD_BG_PID"

        rlRun "sleep 2" 0 "Waiting for rsyslog to initialize"
        rlAssertExists "$SOCKET"

    rlPhaseEnd

    rlPhaseStartTest
        rlLog "Sending 1000 messages via imuxsock to trigger rate limiting"
        rlRun "seq 1 1000 | sed 's/^/msgnum: /' | logger -d -u \"$SOCKET\"" 0 "Sending messages"

        rlLog "Waiting for impstats to flush"
        rlRun "sleep 5"

        rlLog "Contents of stats file:"
        rlRun "cat \"$STATSFILE\""

        rlLog "Verifying impstats includes 250 dropped (discarded) messages"
        rlRun "grep -E -qs 'imuxsock:.*ratelimit\\.discarded=250' \"$STATSFILE\"" 0 "Checking for discarded message counter (exactly 250)"

        rlLog "Checking that 750 messages were logged"
        rlRun "wc -l < \"$LOGFILE\" | grep -q '^750$'" 0 "Checking log file line count (exactly 750)"

    rlPhaseEnd

    rlPhaseStartCleanup
        local pid
        if [ -f "$RSYSLOG_PIDFILE" ] && pid=$(cat "$RSYSLOG_PIDFILE") && kill -0 "$pid" 2>/dev/null; then
            rlLog "Found running rsyslogd with PID $pid, attempting to stop it."
            rlRun "kill $pid" 0,1 "Stopping background rsyslogd"
            # Wait for the specific PID stored in the variable.
            # Exit code 127 is added in case the process is already gone.
            rlRun "wait $pid" 0,1,127 "Waiting for rsyslogd to exit"
        fi
        rsyslogCleanup
    rlPhaseEnd
rlJournalEnd