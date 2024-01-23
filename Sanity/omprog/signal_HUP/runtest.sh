#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Dalibor Pospisil <dapospis@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2024 Red Hat, Inc.
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

rlJournalStart && {
  rlPhaseStartSetup && {
    rlRun "rlImport --all" 0 "Import libraries" || rlDie "cannot continue"
    rlRun "rlCheckMakefileRequires" || rlDie "cannot continue"
    rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
    CleanupRegister "rlRun 'rm -r $TmpDir' 0 'Removing tmp directory'"
    CleanupRegister 'rlRun "popd"'
    rlRun "pushd $TmpDir"
    CleanupRegister 'rlRun "rsyslogCleanup"'
    rlRun "rsyslogSetup"
    CleanupRegister 'rlRun "rlSEBooleanRestore domain_can_mmap_files logging_syslogd_list_non_security_dirs"'
    rlRun 'rlSEBooleanOn domain_can_mmap_files logging_syslogd_list_non_security_dirs'
    CleanupRegister 'rlRun "rlServiceRestore rsyslog"'
    rlRun "rlServiceStop rsyslog"
    CleanupRegister 'rlRun "rlFileRestore"'
    rlRun "rlFileBackup --clean /etc/rsyslog.conf /etc/rsyslog.d/ /usr/libexec/rsyslog/log_rotate.sh /etc/logrotate.d/test /var/log/logs/"
    rlRun "mkdir -p /usr/libexec/rsyslog"
    rsyslogConfigAddTo --begin "MODULES" < <(rsyslogConfigCreateSection "MODLOAD OMPROG")
    rsyslogConfigAddTo "MODLOAD OMPROG" <<EOF
module(load="omprog")
EOF
# rsyslogConfigAddTo "GLOBALS" <<EOF
# global()
# EOF
rsyslogConfigAddTo --begin "RULES" <<EOF
if (\$programname startswith 'module_execution_') then {
  action(type="omprog"
       binary="/usr/libexec/rsyslog/log_rotate.sh")
}
EOF
    rsyslogConfigAddTo "MODLOAD IMUXSOCK" <<EOF
input(type="imuxsock" Socket="/dev/log2")
EOF
    cat > /usr/libexec/rsyslog/log_rotate.sh << 'EOF'
#!/bin/bash
exec >> /var/log/logs/test.out
exec 2>&1
file=/var/log/logs/test.log
echo "before SIGHUP" >> "$file"
#/usr/bin/systemctl --signal=HUP kill rsyslog 2> /dev/null
#/usr/bin/pkill -HUP rsyslogd
#/usr/bin/kill -HUP `cat /var/run/rsyslogd.pid`
sleep 1
echo "after SIGHUP" >> "$file"
:
EOF
    rlRun "chmod a+x /usr/libexec/rsyslog/log_rotate.sh"
    rlRun "restorecon -Rv /usr/libexec/rsyslog/log_rotate.sh"
    rlRun "mkdir -p /var/log/logs"
    CleanupRegister 'rlRun "rlServiceRestore rsyslog"'
    rlRun "rsyslogPrintEffectiveConfig -n"
  rlPhaseEnd; }

  rlPhaseStartTest "send signal using systemctl" && {
    sed -ri 's/^[^#].*kill/#\0/' /usr/libexec/rsyslog/log_rotate.sh
    sed -ri 's/#(.*systemctl)/\1/' /usr/libexec/rsyslog/log_rotate.sh
    rlRun "cat /usr/libexec/rsyslog/log_rotate.sh"
    > /var/log/logs/test.log
    rlRun "rlServiceStart rsyslog"
    rlRun "rsyslogServiceStatus"
    rlRun "logger -u /dev/log2 -t module_execution__test 'test'" 0 "trigger the omprog"
    rlRun "sleep 2s"
    rlRun -s "cat /var/log/logs/test.log"
    rlAssertGrep "before SIGHUP" $rlRun_LOG
    rlAssertGrep "after SIGHUP" $rlRun_LOG
    rlRun "cat /var/log/logs/test.out" 0-255
  rlPhaseEnd; }

  rlPhaseStartTest "send signal using pkill" && {
    sed -ri 's/^[^#].*kill/#\0/' /usr/libexec/rsyslog/log_rotate.sh
    sed -ri 's|#(.*/pkill)|\1|' /usr/libexec/rsyslog/log_rotate.sh
    rlRun "cat /usr/libexec/rsyslog/log_rotate.sh"
    > /var/log/logs/test.log
    rlRun "rlServiceStart rsyslog"
    rlRun "rsyslogServiceStatus"
    rlRun "logger -u /dev/log2 -t module_execution__test 'test'" 0 "trigger the omprog"
    rlRun "sleep 2s"
    rlRun -s "cat /var/log/logs/test.log"
    rlAssertGrep "before SIGHUP" $rlRun_LOG
    rlAssertGrep "after SIGHUP" $rlRun_LOG
    rlRun "cat /var/log/logs/test.out" 0-255
  rlPhaseEnd; }

  rlPhaseStartTest "send signal using kill" && {
    sed -ri 's/^[^#].*kill/#\0/' /usr/libexec/rsyslog/log_rotate.sh
    sed -ri 's|#(.*/kill)|\1|' /usr/libexec/rsyslog/log_rotate.sh
    rlRun "cat /usr/libexec/rsyslog/log_rotate.sh"
    > /var/log/logs/test.log
    rlRun "rlServiceStart rsyslog"
    rlRun "rsyslogServiceStatus"
    rlRun "logger -u /dev/log2 -t module_execution__test 'test'" 0 "trigger the omprog"
    rlRun "sleep 2s"
    rlRun -s "cat /var/log/logs/test.log"
    rlAssertGrep "before SIGHUP" $rlRun_LOG
    rlAssertGrep "after SIGHUP" $rlRun_LOG
    rlRun "cat /var/log/logs/test.out" 0-255
  rlPhaseEnd; }

  rlPhaseStartCleanup && {
    CleanupDo
  rlPhaseEnd; }
  rlJournalPrintText
rlJournalEnd; }
