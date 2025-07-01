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
RSYSLOG_CONF="/tmp/rsyslog-test.conf"
LOGFILE="/tmp/rsyslog-test.log"
RSYSLOG_PIDFILE="/tmp/rsyslog-test.pid"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm "$PACKAGE"

        rlRun "rm -f \"$SOCKET\" \"$STATSFILE\" \"$LOGFILE\" \"$RSYSLOG_PIDFILE\" \"$RSYSLOG_CONF\"" 0 "Clean up any pre-existing files"
        rlRun "systemctl stop rsyslog" 0 "Stopping system rsyslog"
        rlFileBackup "/etc/rsyslog.conf" # Backup the system's rsyslog.conf

        rlRun "cat > \"$RSYSLOG_CONF\" << EOF
# Minimal rsyslog configuration for this test
module(load=\"imuxsock\")
input(type=\"imuxsock\" Socket=\"$SOCKET\" CreatePath=\"on\"
      RateLimit.Interval=\"1\" RateLimit.Burst=\"750\")

module(load=\"impstats\" log.file=\"$STATSFILE\" interval=\"1\" ruleset=\"stats\" log.syslog=\"off\")

template(name=\"outfmt\" type=\"string\" string=\"%msg%\\n\")

ruleset(name=\"stats\") {
    stop # Discard stats messages after processing by impstats
}

# Using property filter syntax for regex matching
:msg, regex, \"msgnum:.*\" action(type=\"omfile\" file=\"$LOGFILE\" template=\"outfmt\")
EOF" 0 "Writing custom rsyslog config"

        rlRun "rsyslogd -N1 -f \"$RSYSLOG_CONF\" | tee /tmp/rsyslog-check.log" 0 "Validating rsyslog config"
        # Ensure the log file exists before grepping, and quote pattern for grep
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
        rlRun "sleep 5" # Increased sleep to ensure impstats has multiple intervals to flush

        rlAssertExists "$STATSFILE"
        rlLog "Contents of stats file:"
        rlRun "cat \"$STATSFILE\""

        rlLog "Verifying impstats includes 250 dropped (discarded) messages"
        rlRun "grep -E -qs 'imuxsock:.*ratelimit\\.discarded=250' \"$STATSFILE\"" 0 "Checking for discarded message counter (exactly 250)"

        rlLog "Checking that 750 messages were logged"
        rlRun "wc -l < \"$LOGFILE\" | grep -q '^750$'" 0 "Checking log file line count (exactly 750)"

    rlPhaseEnd

    rlPhaseStartCleanup
        rlLog "Performing final cleanup actions."
        rlRun "rm -f \"$SOCKET\" \"$STATSFILE\" \"$LOGFILE\" \"$RSYSLOG_CONF\"" 0 "Removing temporary files"
        # Kill the directly run rsyslogd if it's still running
        if [ -f "$RSYSLOG_PIDFILE" ]; then
            rlRun "kill \$(cat \"$RSYSLOG_PIDFILE\")" 0 "Killing custom rsyslogd"
            rlRun "rm -f \"$RSYSLOG_PIDFILE\"" 0 "Removing PID file"
        fi
        rlFileRestore # This restores original /etc/rsyslog.conf
        rlRun "systemctl daemon-reload" 0 "Reloading systemd daemons"
        rlRun "systemctl start rsyslog || :" 0 "Starting system rsyslog (if it was active)"
    rlPhaseEnd
rlJournalEnd