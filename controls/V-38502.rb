control 'V-38502' do
  title 'The /etc/shadow file must be owned by root.'
  desc  "The \"/etc/shadow\" file contains the list of local system accounts
and stores password hashes. Protection of this file is critical for system
security. Failure to give ownership of this file to root provides the
designated owner with access to sensitive information which could weaken the
system security posture."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38502'
  tag "rid": 'SV-50303r1_rule'
  tag "stig_id": 'RHEL-06-000033'
  tag "fix_id": 'F-43449r1_fix'
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
  tag "check": "To check the ownership of \"/etc/shadow\", run the command:

$ ls -l /etc/shadow

If properly configured, the output should indicate the following owner:
\"root\"
If it does not, this is a finding."
  tag "fix": "To properly set the owner of \"/etc/shadow\", run the command:

# chown root /etc/shadow"

  describe file('/etc/shadow') do
    it { should exist }
  end
  describe file('/etc/shadow') do
    its('uid') { should cmp 0 }
  end
end
