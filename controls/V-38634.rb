control "V-38634" do
  title "The system must rotate audit log files that reach the maximum file
size."
  desc  "Automatically rotating logs (by setting this to \"rotate\") minimizes
the chances of the system unexpectedly running out of disk space by being
overwhelmed with log data. However, for systems that must never discard log
data, or which use external processes to transfer it and reclaim space,
\"keep_logs\" can be employed."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38634"
  tag "rid": "SV-50435r2_rule"
  tag "stig_id": "RHEL-06-000161"
  tag "fix_id": "F-43583r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "Inspect \"/etc/audit/auditd.conf\" and locate the following
line to determine if the system is configured to rotate logs when they reach
their maximum size:

# grep max_log_file_action /etc/audit/auditd.conf
max_log_file_action = rotate

If the \"keep_logs\" option is configured for the \"max_log_file_action\" line
in \"/etc/audit/auditd.conf\" and an alternate process is in place to ensure
audit data does not overwhelm local audit storage, this is not a finding.

If the system has not been properly set up to rotate audit logs, this is a
finding."
  tag "fix": "The default action to take when the logs reach their maximum size
is to rotate the log files, discarding the oldest one. To configure the action
taken by \"auditd\", add or correct the line in \"/etc/audit/auditd.conf\":

max_log_file_action = [ACTION]

Possible values for [ACTION] are described in the \"auditd.conf\" man page.
These include:

\"ignore\"
\"syslog\"
\"suspend\"
\"rotate\"
\"keep_logs\"


Set the \"[ACTION]\" to \"rotate\" to ensure log rotation occurs. This is the
default. The setting is case-insensitive."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

