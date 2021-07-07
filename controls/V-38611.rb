control "V-38611" do
  title "The SSH daemon must ignore .rhosts files."
  desc  "SSH trust relationships mean a compromise on one host can allow an
attacker to move trivially to other hosts."
  impact 'medium'
  tag "gtitle": "SRG-OS-000106"
  tag "gid": "V-38611"
  tag "rid": "SV-50412r1_rule"
  tag "stig_id": "RHEL-06-000234"
  tag "fix_id": "F-43559r1_fix"
  tag "cci": ["CCI-000766"]
  tag "nist": ["IA-2 (2)", "Rev_4"]
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
  desc 'check', "To determine how the SSH daemon's \"IgnoreRhosts\" option is
set, run the following command:

# grep -i IgnoreRhosts /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value \"yes\" is
returned, then the required value is set.
If the required value is not set, this is a finding."
  desc 'fix', "SSH can emulate the behavior of the obsolete rsh command in
allowing users to enable insecure access to their accounts via \".rhosts\"
files.

To ensure this behavior is disabled, add or correct the following line in
\"/etc/ssh/sshd_config\":

IgnoreRhosts yes"

  describe sshd_config do
    its('IgnoreRhosts') { should (eq 'yes').or be_nil }
  end
end

