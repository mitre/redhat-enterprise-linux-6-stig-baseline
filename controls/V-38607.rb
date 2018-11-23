control 'V-38607' do
  title 'The SSH daemon must be configured to use only the SSHv2 protocol.'
  desc  "SSH protocol version 1 suffers from design flaws that result in
security vulnerabilities and should not be used."
  impact 0.7
  tag "gtitle": 'SRG-OS-000112'
  tag "gid": 'V-38607'
  tag "rid": 'SV-50408r1_rule'
  tag "stig_id": 'RHEL-06-000227'
  tag "fix_id": 'F-43555r1_fix'
  tag "cci": ['CCI-000774']
  tag "nist": ['IA-2 (8)', 'Rev_4']
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
  tag "check": "To check which SSH protocol version is allowed, run the
following command:

# grep Protocol /etc/ssh/sshd_config

If configured properly, output should be

Protocol 2


If it is not, this is a finding."
  tag "fix": "Only SSH protocol version 2 connections should be permitted. The
default setting in \"/etc/ssh/sshd_config\" is correct, and can be verified by
ensuring that the following line appears:

Protocol 2"

  describe sshd_config do
    its('Protocol') { should cmp 2 }
  end
end
