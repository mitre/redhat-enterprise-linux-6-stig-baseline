control "V-38612" do
  title "The SSH daemon must not allow host-based authentication."
  desc  "SSH trust relationships mean a compromise on one host can allow an
attacker to move trivially to other hosts."
  impact 0.5
  tag "gtitle": "SRG-OS-000106"
  tag "gid": "V-38612"
  tag "rid": "SV-50413r1_rule"
  tag "stig_id": "RHEL-06-000236"
  tag "fix_id": "F-43560r1_fix"
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
  tag "check": "To determine how the SSH daemon's \"HostbasedAuthentication\"
option is set, run the following command:

# grep -i HostbasedAuthentication /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value \"no\" is
returned, then the required value is set.
If the required value is not set, this is a finding."
  tag "fix": "SSH's cryptographic host-based authentication is more secure than
\".rhosts\" authentication, since hosts are cryptographically authenticated.
However, it is not recommended that hosts unilaterally trust one another, even
within an organization.

To disable host-based authentication, add or correct the following line in
\"/etc/ssh/sshd_config\":

HostbasedAuthentication no"

  describe sshd_config do
    its('HostbasedAuthentication') { should (eq 'no').or be_nil }
  end
end

