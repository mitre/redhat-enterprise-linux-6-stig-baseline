control 'V-38493' do
  title 'Audit log directories must have mode 0755 or less permissive.'
  desc  "If users can delete audit logs, audit trails can be modified or
destroyed."
  impact 0.5
  tag "gtitle": 'SRG-OS-000059'
  tag "gid": 'V-38493'
  tag "rid": 'SV-50294r1_rule'
  tag "stig_id": 'RHEL-06-000385'
  tag "fix_id": 'F-43440r1_fix'
  tag "cci": ['CCI-000164']
  tag "nist": ['AU-9', 'Rev_4']
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
  tag "check": "Run the following command to check the mode of the system audit
directories:

grep \"^log_file\" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs stat -c %a:%n

Audit directories must be mode 0755 or less permissive.
If any are more permissive, this is a finding."
  tag "fix": "Change the mode of the audit log directories with the following
command:

# chmod go-w [audit_directory]"

  log_file = command("grep \"^log_file\" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'").stdout.strip
  describe file(log_file) do
    it { should exist }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('others') }
  end
end
