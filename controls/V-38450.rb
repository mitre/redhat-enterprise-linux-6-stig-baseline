control 'V-38450' do
  title 'The /etc/passwd file must be owned by root.'
  desc  "The \"/etc/passwd\" file contains information about the users that are
configured on the system. Protection of this file is critical for system
security."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38450'
  tag "rid": 'SV-50250r1_rule'
  tag "stig_id": 'RHEL-06-000039'
  tag "fix_id": 'F-43395r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "To check the ownership of \"/etc/passwd\", run the command:

$ ls -l /etc/passwd

If properly configured, the output should indicate the following owner:
\"root\"
If it does not, this is a finding."
  tag "fix": "To properly set the owner of \"/etc/passwd\", run the command:

# chown root /etc/passwd"

  describe file('/etc/passwd') do
    it { should exist }
  end
  describe file('/etc/passwd') do
    its('uid') { should cmp 0 }
  end
end
