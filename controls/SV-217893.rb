# encoding: UTF-8

control "SV-217893" do
  title "The system must require passwords to contain at least one uppercase alphabetic character."
  desc "Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space."
  desc "default", "Requiring a minimum number of uppercase characters makes password
guessing attacks more difficult by ensuring a larger search space."
  desc "check", "To check how many uppercase characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

Note: The \"ucredit\" parameter (as a negative number) will indicate how many uppercase characters are required. The DoD requires at least one uppercase character in a password. This would appear as \"ucredit=-1\". 

If “ucredit” is not found or not set to the required value, this is a finding."
  desc "fix", "The pam_cracklib module's \"ucredit=\" parameter controls requirements for usage of uppercase letters in a password. When set to a negative number, any password will be required to contain that many uppercase characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each uppercase character. 

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding \"ucredit=-1\" after pam_cracklib.so to require use of an uppercase character in passwords."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000069"
  tag gid: "V-217893"
  tag rid: "SV-217893r603264_rule"
  tag stig_id: "RHEL-06-000057"
  tag fix_id: "F-19372r462377_fix"
  tag cci: ["CCI-000192"]
  tag nist: ["IA-5 (1) (a)", "Rev_4"]

  describe.one do
    describe file("/etc/pam.d/system-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+ucredit=-(\d+)[^\n\r]*$/) }
    end
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+ucredit=-(\d+)[^\n\r]*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
    describe file("/etc/pam.d/system-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+ucredit=-(\d+)\s+.*$/) }
    end
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+ucredit=-(\d+)\s+.*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
  end
  describe.one do
    describe file("/etc/pam.d/password-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+ucredit=-(\d+)[^\n\r]*$/) }
    end
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+ucredit=-(\d+)[^\n\r]*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
    describe file("/etc/pam.d/password-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+ucredit=-(\d+)\s+.*$/) }
    end
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+ucredit=-(\d+)\s+.*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 1 }
      end
    end
  end
end