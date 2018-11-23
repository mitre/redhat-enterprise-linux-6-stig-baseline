control 'V-38658' do
  title "The system must prohibit the reuse of passwords within five
iterations."
  desc  "Preventing reuse of previous passwords helps ensure that a compromised
password is not reused by a user."
  impact 0.5
  tag "gtitle": 'SRG-OS-000077'
  tag "gid": 'V-38658'
  tag "rid": 'SV-50459r6_rule'
  tag "stig_id": 'RHEL-06-000274'
  tag "fix_id": 'F-43608r6_fix'
  tag "cci": ['CCI-000200']
  tag "nist": ['IA-5 (1) (e)', 'Rev_4']
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
  tag "check": "To verify the password reuse setting is compliant, run the
following command:

# grep remember /etc/pam.d/system-auth /etc/pam.d/password-auth

If the line is commented out, the line does not contain \"password required
pam_pwhistory.so\" or \"password requisite pam_pwhistory.so\", or the value for
\"remember\" is less than \"5\", this is a finding."
  tag "fix": "Do not allow users to reuse recent passwords. This can be
accomplished by using the \"remember\" option for the \"pam_pwhistory\" PAM
module. In the file \"/etc/pam.d/system-auth\" and /etc/pam.d/password-auth,
append \"remember=5\" to the lines that refer to the \"pam_pwhistory.so\"
module, as shown:

password required pam_pwhistory.so [existing_options] remember=5

or

password requisite pam_pwhistory.so [existing_options] remember=5

The DoD requirement is five passwords."

  describe.one do
    describe file('/etc/pam.d/system-auth') do
      its('content') { should match(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[\t ]+[^#\n\r]*\s+remember=(\d+)(?:(?:\s)|(?:$))/) }
    end
    file('/etc/pam.d/system-auth').content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[\t ]+[^#\n\r]*\s+remember=(\d+)(?:(?:\s)|(?:$))/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 5 }
      end
    end
    describe file('/etc/pam.d/system-auth') do
      its('content') { should match(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so\s+remember=(\d+)(?:(?:\s)|(?:$))/) }
    end
    file('/etc/pam.d/system-auth').content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so\s+remember=(\d+)(?:(?:\s)|(?:$))/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 5 }
      end
    end
  end
  describe.one do
    describe file('/etc/pam.d/password-auth') do
      its('content') { should match(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[\t ]+[^#\n\r]*\s+remember=(\d+)(?:(?:\s)|(?:$))/) }
    end
    file('/etc/pam.d/password-auth').content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so[\t ]+[^#\n\r]*\s+remember=(\d+)(?:(?:\s)|(?:$))/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 5 }
      end
    end
    describe file('/etc/pam.d/password-auth') do
      its('content') { should match(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so\s+remember=(\d+)(?:(?:\s)|(?:$))/) }
    end
    file('/etc/pam.d/password-auth').content.to_s.scan(/^\s*password\s+(?:(?:requisite)|(?:required))\s+pam_pwhistory\.so\s+remember=(\d+)(?:(?:\s)|(?:$))/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 5 }
      end
    end
  end
end
