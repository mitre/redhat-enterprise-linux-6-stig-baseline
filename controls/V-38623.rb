control "V-38623" do
  title "All rsyslog-generated log files must have mode 0600 or less
permissive."
  desc  "Log files can contain valuable information regarding system
configuration. If the system log files are not protected, unauthorized users
could change the logged data, eliminating their forensic value."
  impact 0.5
  tag "gtitle": "SRG-OS-000206"
  tag "gid": "V-38623"
  tag "rid": "SV-50424r2_rule"
  tag "stig_id": "RHEL-06-000135"
  tag "fix_id": "F-43571r1_fix"
  tag "cci": ["CCI-001314"]
  tag "nist": ["SI-11 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "The file permissions for all log files written by rsyslog
should be set to 600, or more restrictive. These log files are determined by
the second part of each Rule line in \"/etc/rsyslog.conf\" and typically all
appear in \"/var/log\". For each log file [LOGFILE] referenced in
\"/etc/rsyslog.conf\", run the following command to inspect the file's
permissions:

$ ls -l [LOGFILE]

The permissions should be 600, or more restrictive. Some log files referenced
in /etc/rsyslog.conf may be created by other programs and may require exclusion
from consideration.

If the permissions are not correct, this is a finding."
  tag "fix": "The file permissions for all log files written by rsyslog should
be set to 600, or more restrictive. These log files are determined by the
second part of each Rule line in \"/etc/rsyslog.conf\" and typically all appear
in \"/var/log\". For each log file [LOGFILE] referenced in
\"/etc/rsyslog.conf\", run the following command to inspect the file's
permissions:

$ ls -l [LOGFILE]

If the permissions are not 600 or more restrictive, run the following command
to correct this:

# chmod 0600 [LOGFILE]"

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

