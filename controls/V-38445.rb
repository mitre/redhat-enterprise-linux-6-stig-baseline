control "V-38445" do
  title "Audit log files must be group-owned by root."
  desc  "If non-privileged users can write to audit logs, audit trails can be
modified or destroyed."
  impact 0.5
  tag "gtitle": "SRG-OS-000057"
  tag "gid": "V-38445"
  tag "rid": "SV-50245r2_rule"
  tag "stig_id": "RHEL-06-000522"
  tag "fix_id": "F-43390r1_fix"
  tag "cci": ["CCI-000162"]
  tag "nist": ["AU-9", "Rev_4"]
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
  tag "check": "Run the following command to check the group owner of the
system audit logs:

grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %G:%n

Audit logs must be group-owned by root.
If they are not, this is a finding."
  tag "fix": "Change the group owner of the audit log files with the following
command:

# chgrp root [audit_file]"

  describe command("grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %G:%n") do
    its('stdout.lines') { should all match %{^root:} }
  end
end

