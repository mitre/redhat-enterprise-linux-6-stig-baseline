control 'V-38495' do
  title 'Audit log files must be owned by root.'
  desc  "If non-privileged users can write to audit logs, audit trails can be
modified or destroyed."
  impact 0.5
  tag "gtitle": 'SRG-OS-000057'
  tag "gid": 'V-38495'
  tag "rid": 'SV-50296r1_rule'
  tag "stig_id": 'RHEL-06-000384'
  tag "fix_id": 'F-43443r1_fix'
  tag "cci": ['CCI-000162']
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
  tag "check": "Run the following command to check the owner of the system
audit logs:

grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %U:%n

Audit logs must be owned by root.
If they are not, this is a finding."
  tag "fix": "Change the owner of the audit log files with the following
command:

# chown root [audit_file]"

  describe command('find /var/log/audit -regex .\\*/\\^.\\*\\$ -user 0') do
    its('stdout') { should_not be_empty }
  end
  describe command('find /var/log/audit -type d -user 0') do
    its('stdout') { should_not be_empty }
  end
end
