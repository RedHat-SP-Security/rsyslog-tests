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
rsyslogConfigAddTo --begin "RULES" <<EOF
if (\$programname startswith 'module_execution_') then {
  action(type="omprog"
       binary="/usr/libexec/rsyslog/log_rotate.sh")
}
EOF
    rsyslogConfigAddTo "MODLOAD IMUXSOCK" <<EOF
input(type="imuxsock" Socket="/dev/log2" SysSock.RateLimit.Interval="0" SysSock.RateLimit.Burst="0")
EOF
    cat > /usr/libexec/rsyslog/log_rotate.sh << 'EOF'
#!/bin/bash
exec >> /var/log/logs/test.out
exec 2>&1
file=/var/log/logs/test.log
while read -r line; do
  echo "$line" >> "$file"
done
:
EOF
    rlRun "chmod a+x /usr/libexec/rsyslog/log_rotate.sh"
    rlRun "restorecon -Rv /usr/libexec/rsyslog/log_rotate.sh"
    rlRun "mkdir -p /var/log/logs"
    CleanupRegister 'rlRun "rlServiceRestore rsyslog"'
    rlRun "rlServiceStart rsyslog"
  rlPhaseEnd; }

    rlPhaseStartTest && {
      rlRun "logger -u /dev/log2 -t module_execution__test 'test1'"
      rlRun "sleep 1s"
      rlRun -s "cat /var/log/logs/test.log"
      rlAssertGrep test1 $rlRun_LOG

      rlRun "logger -u /dev/log2 -t module_execution__test 'test2'"
      rlRun "sleep 1s"
      rlRun -s "cat /var/log/logs/test.log"
      rlAssertGrep test1 $rlRun_LOG
      rlAssertGrep test2 $rlRun_LOG

      rlRun "systemctl --signal=HUP kill rsyslog"
      rlRun "logger -u /dev/log2 -t module_execution__test 'test3'"
      rlRun "sleep 1s"
      rlRun -s "cat /var/log/logs/test.log"
      rlAssertGrep test1 $rlRun_LOG
      rlAssertGrep test2 $rlRun_LOG
      rlAssertGrep test3 $rlRun_LOG

      rlRun "pkill --signal HUP rsyslogd"
      rlRun "logger -u /dev/log2 -t module_execution__test 'test4'"
      rlRun "sleep 1s"
      rlRun -s "cat /var/log/logs/test.log"
      rlAssertGrep test1 $rlRun_LOG
      rlAssertGrep test2 $rlRun_LOG
      rlAssertGrep test3 $rlRun_LOG
      rlAssertGrep test4 $rlRun_LOG
    rlPhaseEnd; }

  rlPhaseStartCleanup && {
    CleanupDo
  rlPhaseEnd; }
  rlJournalPrintText
rlJournalEnd; }
