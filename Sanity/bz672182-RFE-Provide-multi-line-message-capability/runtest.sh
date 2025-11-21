#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rsyslog/Sanity/bz672182-RFE-Provide-multi-line-message-capability
#   Description: Test for bz672182 ([RFE] Provide multi-line message capability)?
#   Author: Dalibor Pospisil <dapospis@dapospis.redhat>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2012 Red Hat, Inc. All rights reserved.
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
PACKAGE="${BASEOS_CI_COMPONENT:-$PACKAGE}"

rlJournalStart
    rlPhaseStartSetup
      rlRun "rlImport --all" || rlDie 'cannot continue'
      rlRun "rlCheckRecommended; rlCheckRequired" || rlDie "cannot continue"
      tcfTry "Setup phase" && {
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        CleanupRegister "rlRun 'rm -rf $TmpDir' 0 'Removing tmp directory'"
        CleanupRegister 'rlRun "popd"'
        rlRun "pushd $TmpDir"
        CleanupRegister 'rlRun "rm -f /var/log/messages_localhost"'
        CleanupRegister 'rsyslogServiceRestore'
        CleanupRegister 'rlRun "rlFileRestore"'
        rlRun "rlFileBackup --clean '/etc/rsyslog.conf'"
        rsyslogPrepareConf
        tcfTry "Configure rsyslog" && { #{{{
          rsyslogConfigIsNewSyntax && rsyslogConfigAppend "MODULES" /etc/rsyslog.conf <<EOF
module(load="imtcp" DisableLFDelimiter="on" AddtlFrameDelimiter="76")

template(name="RemoteHost" type="string" string="/var/log/messages_%HOSTNAME%")

ruleset(name="remote"){ ##############################
*.* ?RemoteHost
}

input(type="imtcp" port="50514" ruleset="remote")
EOF

          rsyslogConfigIsNewSyntax || rsyslogConfigAppend "MODULES" /etc/rsyslog.conf <<EOF
\$ModLoad imtcp
\$InputTCPServerDisableLFDelimiter on
\$InputTCPServerAddtlFrameDelimiter 76
#\$template RemoteHost,"$TmpDir/syslog_%HOSTNAME%/messages"
\$template RemoteHost,"/var/log/messages_%HOSTNAME%"
# Remote Logging
\$RuleSet remote
*.* ?RemoteHost
\$InputTCPServerBindRuleset remote
\$InputTCPServerRun 50514
EOF
          #}}}
        tcfFin; }
        CleanupRegister 'rlRun "rlSEPortRestore"'
        # Pre-cleanup: Delete the port first to avoid conflicts from a previous failed run
        # In Fedora 43+, port 50514 may be in the default policy, so try to delete it
        # from local customizations first (will fail if not there, that's OK)
        rlRun "semanage port -d -t syslogd_port_t -p tcp 50514 || true" 0 "Pre-cleaning SELinux port"
        # Check if port already has correct type (e.g., in base policy on Fedora 43+)
        if semanage port -l | grep -q "^syslogd_port_t.*tcp.*50514"; then
          rlLog "Port 50514 already has type syslogd_port_t, skipping add"
        else
          # Port doesn't exist or has wrong type, add it
          rlRun "rlSEPortAdd tcp 50514 syslogd_port_t" 0-255
        fi
        rlRun "rsyslogPrintEffectiveConfig -n"
        rlRun "rsyslogServiceStart"
      tcfFin; }
    rlPhaseEnd

    rlPhaseStartTest
      tcfTry "Test phase" && {
        if rsyslogVersion '<5' && rpm -q rsyslog; then
          rlLog "This case is valid on RHEL-5 only for rsyslog5"
        else
          rlRun "netstat -putna"
          rlRun "echo -e \"localhost 1r\r2r\n3rL\" | nc -w 1 127.0.0.1 50514"
          sleep 1s
          rlAssertGrep "1r#0152r#0123r" /var/log/messages_localhost
        fi
      tcfFin; }
      #PS1='[test] ' bash
    rlPhaseEnd

    rlPhaseStartCleanup
      CleanupDo
      tcfCheckFinal
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
