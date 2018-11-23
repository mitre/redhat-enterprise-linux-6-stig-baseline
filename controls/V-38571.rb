control 'V-38571' do
  title "The system must require passwords to contain at least one lower-case
alphabetic character."
  desc  "Requiring a minimum number of lower-case characters makes password
guessing attacks more difficult by ensuring a larger search space."
  impact 0.3
  tag "gtitle": 'SRG-OS-000070'
  tag "gid": 'V-38571'
  tag "rid": 'SV-50372r3_rule'
  tag "stig_id": 'RHEL-06-000059'
  tag "fix_id": 'F-43519r3_fix'
  tag "cci": ['CCI-000193']
  tag "nist": ['IA-5 (1) (a)', 'Rev_4']
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
  tag "check": "To check how many lower-case characters are required in a
password, run the following command:

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

Note: The \"lcredit\" parameter (as a negative number) will indicate how many
lower-case characters are required. The DoD requires at least one lower-case
character in a password. This would appear as \"lcredit=-1\".

If \"lcredit\" is not found or not set to the required value, this is a finding."
  tag "fix": "The pam_cracklib module's \"lcredit=\" parameter controls
requirements for usage of lower-case letters in a password. When set to a
negative number, any password will be required to contain that many lower-case
characters.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding \"lcredit=-1\"
after pam_cracklib.so to require use of a lower-case character in passwords.
"

  describe.one do
    describe file('/etc/pam.d/system-auth') do
      its('content') { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+lcredit=-(\d+)[^\n\r]*$/) }
    end
    file('/etc/pam.d/system-auth').content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+lcredit=-(\d+)[^\n\r]*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
    describe file('/etc/pam.d/system-auth') do
      its('content') { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+lcredit=-(\d+)\s+.*$/) }
    end
    file('/etc/pam.d/system-auth').content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+lcredit=-(\d+)\s+.*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
  end
  describe.one do
    describe file('/etc/pam.d/password-auth') do
      its('content') { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+lcredit=-(\d+)[^\n\r]*$/) }
    end
    file('/etc/pam.d/password-auth').content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+lcredit=-(\d+)[^\n\r]*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
    describe file('/etc/pam.d/password-auth') do
      its('content') { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+lcredit=-(\d+)\s+.*$/) }
    end
    file('/etc/pam.d/password-auth').content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+lcredit=-(\d+)\s+.*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
  end
end
