control "V-38680" do
  title "The audit system must identify staff members to receive notifications
of audit log storage volume capacity issues."
  desc  "Email sent to the root account is typically aliased to the
administrators of the system, who can take appropriate action."
  impact 'medium'
  tag "gtitle": "SRG-OS-000046"
  tag "gid": "V-38680"
  tag "rid": "SV-50481r1_rule"
  tag "stig_id": "RHEL-06-000313"
  tag "fix_id": "F-43629r1_fix"
  tag "cci": ["CCI-000139"]
  tag "nist": ["AU-5 a", "Rev_4"]
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
  desc 'check', "Inspect \"/etc/audit/auditd.conf\" and locate the following
line to determine if the system is configured to send email to an account when
it needs to notify an administrator:

action_mail_acct = root


If auditd is not configured to send emails per identified actions, this is a
finding."
  desc 'fix', "The \"auditd\" service can be configured to send email to a
designated account in certain situations. Add or correct the following line in
\"/etc/audit/auditd.conf\" to ensure that administrators are notified via email
for those situations:

action_mail_acct = root"

  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^action_mail_acct\s*=\s*(\S+)\s*$/) }
  end
  file("/etc/audit/auditd.conf").content.to_s.scan(/^action_mail_acct\s*=\s*(\S+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should eq "root" }
    end
  end
end

