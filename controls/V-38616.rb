control "V-38616" do
  title "The SSH daemon must not permit user environment settings."
  desc  "SSH environment options potentially allow users to bypass access
restriction in some configurations."
  impact 0.3
  tag "gtitle": "SRG-OS-000242"
  tag "gid": "V-38616"
  tag "rid": "SV-50417r1_rule"
  tag "stig_id": "RHEL-06-000241"
  tag "fix_id": "F-43565r1_fix"
  tag "cci": ["CCI-001414"]
  tag "nist": ["AC-4", "Rev_4"]
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
  tag "check": "To ensure users are not able to present environment daemons,
run the following command:

# grep PermitUserEnvironment /etc/ssh/sshd_config

If properly configured, output should be:

PermitUserEnvironment no


If it is not, this is a finding."
  tag "fix": "To ensure users are not able to present environment options to
the SSH daemon, add or correct the following line in \"/etc/ssh/sshd_config\":

PermitUserEnvironment no"

  describe "SCAP oval - Nested OR logic is not supported - see https://github.com/inspec/inspec/issues/3379" do
    skip "SCAP oval - Nested OR logic is not supported - see https://github.com/inspec/inspec/issues/3379"
  end
end

