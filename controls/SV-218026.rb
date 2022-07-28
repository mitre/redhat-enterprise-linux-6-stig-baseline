# encoding: UTF-8

control "SV-218026" do
  title "The system must prohibit the reuse of passwords within five iterations."
  desc "Preventing reuse of previous passwords helps ensure that a compromised password is not reused by a user."
  desc "default", "Preventing reuse of previous passwords helps ensure that a compromised
password is not reused by a user."
  desc "check", "To verify the password reuse setting is compliant, run the following command:

# grep remember /etc/pam.d/system-auth /etc/pam.d/password-auth

If the line is commented out, the line does not contain \"password required pam_pwhistory.so\" or \"password requisite pam_pwhistory.so\", or the value for \"remember\" is less than “5”, this is a finding."
  desc "fix", "Do not allow users to reuse recent passwords. This can be accomplished by using the \"remember\" option for the \"pam_pwhistory\" PAM module. In the file \"/etc/pam.d/system-auth\" and /etc/pam.d/password-auth, append \"remember=5\" to the lines that refer to the \"pam_pwhistory.so\" module, as shown:

password required pam_pwhistory.so [existing_options] remember=5

or

password requisite pam_pwhistory.so [existing_options] remember=5

The DoD requirement is five passwords."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000077"
  tag gid: "V-218026"
  tag rid: "SV-218026r603264_rule"
  tag stig_id: "RHEL-06-000274"
  tag fix_id: "F-19505r462404_fix"
  tag cci: ["CCI-000200"]
  tag nist: ["IA-5 (1) (e)", "Rev_4"]

  describe.one do
    describe file("/etc/pam.d/system-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[\t ]+[^#\n\r]*\s+remember=(\d+)(?:(?:\s)|(?:$))/) }
    end
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[\t ]+[^#\n\r]*\s+remember=(\d+)(?:(?:\s)|(?:$))/).flatten.each do |entry|
      describe entry do
        it { should cmp >= input('min_reuse_generations') }
      end
    end
    describe file("/etc/pam.d/system-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so\s+remember=(\d+)(?:(?:\s)|(?:$))/) }
    end
    file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so\s+remember=(\d+)(?:(?:\s)|(?:$))/).flatten.each do |entry|
      describe entry do
        it { should cmp >= input('min_reuse_generations') }
      end
    end
  end
  describe.one do
    describe file("/etc/pam.d/password-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[\t ]+[^#\n\r]*\s+remember=(\d+)(?:(?:\s)|(?:$))/) }
    end
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[\t ]+[^#\n\r]*\s+remember=(\d+)(?:(?:\s)|(?:$))/).flatten.each do |entry|
      describe entry do
        it { should cmp >= input('min_reuse_generations') }
      end
    end
    describe file("/etc/pam.d/password-auth") do
      its("content") { should match(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so\s+remember=(\d+)(?:(?:\s)|(?:$))/) }
    end
    file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so\s+remember=(\d+)(?:(?:\s)|(?:$))/).flatten.each do |entry|
      describe entry do
        it { should cmp >= input('min_reuse_generations') }
      end
    end
  end
end