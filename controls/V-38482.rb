control "V-38482" do
  title "The system must require passwords to contain at least one numeric
character."
  desc  "Requiring digits makes password guessing attacks more difficult by
ensuring a larger search space."
  impact 0.3
  tag "gtitle": "SRG-OS-000071"
  tag "gid": "V-38482"
  tag "rid": "SV-50282r2_rule"
  tag "stig_id": "RHEL-06-000056"
  tag "fix_id": "F-43427r2_fix"
  tag "cci": ["CCI-000194"]
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
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
  tag "check": "To check how many digits are required in a password, run the
following command:

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

Note: The \"dcredit\" parameter (as a negative number) will indicate how many
digits are required. The DoD requires at least one digit in a password. This
would appear as \"dcredit=-1\".

If “dcredit” is not found or not set to the required value, this is a finding.
"
  tag "fix": "The pam_cracklib module's \"dcredit\" parameter controls
requirements for usage of digits in a password. When set to a negative number,
any password will be required to contain that many digits. When set to a
positive number, pam_cracklib will grant +1 additional length credit for each
digit.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding \"dcredit=-1\"
after pam_cracklib.so to require use of a digit in passwords.
"

  describe.one do
    describe file("/etc/pam.d/system-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+dcredit=-(\d+)[^\n\r]*$/) }
    end
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+dcredit=-(\d+)[^\n\r]*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
    describe file("/etc/pam.d/system-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+dcredit=-(\d+)\s+.*$/) }
    end
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+dcredit=-(\d+)\s+.*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
  end
  describe.one do
    describe file("/etc/pam.d/password-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+dcredit=-(\d+)[^\n\r]*$/) }
    end
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+dcredit=-(\d+)[^\n\r]*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
    describe file("/etc/pam.d/password-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+dcredit=-(\d+)\s+.*$/) }
    end
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+dcredit=-(\d+)\s+.*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
  end
end

