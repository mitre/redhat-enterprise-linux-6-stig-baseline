control "V-38572" do
  title "The system must require at least eight characters be changed between
the old and new passwords during a password change."
  desc  "Requiring a minimum number of different characters during password
changes ensures that newly changed passwords should not resemble previously
compromised ones. Note that passwords which are changed on compromised systems
will still be compromised, however."
  impact 0.3
  tag "gtitle": "SRG-OS-000072"
  tag "gid": "V-38572"
  tag "rid": "SV-50373r3_rule"
  tag "stig_id": "RHEL-06-000060"
  tag "fix_id": "F-43520r4_fix"
  tag "cci": ["CCI-000195"]
  tag "nist": ["IA-5 (1) (b)", "Rev_4"]
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
  tag "check": "To check how many characters must differ during a password
change, run the following command:

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

Note: The \"difok\" parameter will indicate how many characters must differ.
The DoD requires eight characters differ during a password change. This would
appear as \"difok=8\".

If \"difok\" is not found or is set to a value less than \"8\", this is a finding."
  tag "fix": "The pam_cracklib module's \"difok\" parameter controls
requirements for usage of different characters during a password change.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding \"difok=[NUM]\"
after pam_cracklib.so to require differing characters when changing passwords,
substituting [NUM] appropriately. The DoD requirement is 8.
"

  describe.one do
    describe file("/etc/pam.d/system-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+difok=(\d+)[^\n\r]*$/) }
    end
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+difok=(\d+)[^\n\r]*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= attribute('pam_cracklib_difok') }
      end
    end
    describe file("/etc/pam.d/system-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+difok=(\d+)\s+.*$/) }
    end
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+difok=(\d+)\s+.*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= attribute('pam_cracklib_difok') }
      end
    end
  end
  describe.one do
    describe file("/etc/pam.d/password-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+difok=(\d+)[^\n\r]*$/) }
    end
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))[\t ]+[^#\n\r]*\s+difok=(\d+)[^\n\r]*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= attribute('pam_cracklib_difok') }
      end
    end
    describe file("/etc/pam.d/password-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+difok=(\d+)\s+.*$/) }
    end
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:required)|(?:requisite))\s+(?:(?:\/lib\/security\/\$ISA\/pam_cracklib\.so)|(?:pam_cracklib\.so))\s+difok=(\d+)\s+.*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= attribute('pam_cracklib_difok') }
      end
    end
  end
end

