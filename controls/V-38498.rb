control "V-38498" do
  title "Audit log files must have mode 0640 or less permissive."
  desc  "If users can write to audit logs, audit trails can be modified or
destroyed."
  impact 'medium'
  tag "gtitle": "SRG-OS-000058"
  tag "gid": "V-38498"
  tag "rid": "SV-50299r1_rule"
  tag "stig_id": "RHEL-06-000383"
  tag "fix_id": "F-43445r1_fix"
  tag "cci": ["CCI-000163"]
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
  desc 'check', "Run the following command to check the mode of the system audit
logs:

grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %a:%n

Audit logs must be mode 0640 or less permissive.
If any are more permissive, this is a finding."
  desc 'fix', "Change the mode of the audit log files with the following
command:

# chmod 0640 [audit_file]"

  describe command("find /var/log/audit -regex .\\*/\\^.\\*\\$ -perm -07137 -xdev") do
    its("stdout") { should be_empty }
  end
end

