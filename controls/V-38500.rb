control "V-38500" do
  title "The root account must be the only account having a UID of 0."
  desc  "An account has root authority if it has a UID of 0. Multiple accounts
with a UID of 0 afford more opportunity for potential intruders to guess a
password for a privileged account. Proper configuration of sudo is recommended
to afford multiple system administrators access to root privileges in an
accountable manner."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38500"
  tag "rid": "SV-50301r2_rule"
  tag "stig_id": "RHEL-06-000032"
  tag "fix_id": "F-43447r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "To list all password file entries for accounts with UID 0, run
the following command:

# awk -F: '($3 == 0) {print}' /etc/passwd

This should print only one line, for the user root.
If any account other than root has a UID of 0, this is a finding."
  tag "fix": "If any account other than root has a UID of 0, this
misconfiguration should be investigated and the accounts other than root should
be removed or have their UID changed."

  describe file("/etc/passwd") do
    its("content") { should_not match(/^(?!root:)[^:]*:[^:]:0/) }
  end
end

