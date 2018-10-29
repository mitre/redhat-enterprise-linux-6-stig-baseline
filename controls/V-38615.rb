control "V-38615" do
  title "The SSH daemon must be configured with the Department of Defense (DoD)
login banner."
  desc  "The warning message reinforces policy awareness during the logon
process and facilitates possible legal action against attackers. Alternatively,
systems whose ownership should not be obvious should ensure usage of a banner
that does not provide easy attribution."
  impact 0.5
  tag "gtitle": "SRG-OS-000023"
  tag "gid": "V-38615"
  tag "rid": "SV-50416r1_rule"
  tag "stig_id": "RHEL-06-000240"
  tag "fix_id": "F-43563r1_fix"
  tag "cci": ["CCI-000048"]
  tag "nist": ["AC-8 a", "Rev_4"]
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
  tag "check": "To determine how the SSH daemon's \"Banner\" option is set, run
the following command:

# grep -i Banner /etc/ssh/sshd_config

If a line indicating /etc/issue is returned, then the required value is set.
If the required value is not set, this is a finding."
  tag "fix": "To enable the warning banner and ensure it is consistent across
the system, add or correct the following line in \"/etc/ssh/sshd_config\":

Banner /etc/issue

Another section contains information on how to create an appropriate
system-wide warning banner."

  describe "SCAP oval - Nested OR logic is not supported - see https://github.com/inspec/inspec/issues/3379" do
    skip "SCAP oval - Nested OR logic is not supported - see https://github.com/inspec/inspec/issues/3379"
  end
end

