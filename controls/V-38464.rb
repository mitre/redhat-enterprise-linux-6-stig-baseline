control "V-38464" do
  title "The audit system must take appropriate action when there are disk
errors on the audit storage volume."
  desc  "Taking appropriate action in case of disk errors will minimize the
possibility of losing audit records."
  impact 'medium'
  tag "gtitle": "SRG-OS-000047"
  tag "gid": "V-38464"
  tag "rid": "SV-50264r1_rule"
  tag "stig_id": "RHEL-06-000511"
  tag "fix_id": "F-43410r1_fix"
  tag "cci": ["CCI-000140"]
  tag "nist": ["AU-5 b", "Rev_4"]
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
line to determine if the system is configured to take appropriate action when
disk errors occur:

# grep disk_error_action /etc/audit/auditd.conf
disk_error_action = [ACTION]


If the system is configured to \"suspend\" when disk errors occur or \"ignore\"
them, this is a finding."
  desc 'fix', "Edit the file \"/etc/audit/auditd.conf\". Modify the following
line, substituting [ACTION] appropriately:

disk_error_action = [ACTION]

Possible values for [ACTION] are described in the \"auditd.conf\" man page.
These include:

\"ignore\"
\"syslog\"
\"exec\"
\"suspend\"
\"single\"
\"halt\"


Set this to \"syslog\", \"exec\", \"single\", or \"halt\"."

  describe parse_config_file('/etc/audit/auditd.conf') do
    its('disk_error_action') { should_not be_nil }
    its('disk_error_action.downcase') { should_not be_in ['suspend', 'ignore'] }
  end
end

