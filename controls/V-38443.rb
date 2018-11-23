control 'V-38443' do
  title 'The /etc/gshadow file must be owned by root.'
  desc  "The \"/etc/gshadow\" file contains group password hashes. Protection
of this file is critical for system security."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38443'
  tag "rid": 'SV-50243r1_rule'
  tag "stig_id": 'RHEL-06-000036'
  tag "fix_id": 'F-43388r1_fix'
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
  tag "check": "To check the ownership of \"/etc/gshadow\", run the command:

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following owner:
\"root\"
If it does not, this is a finding."
  tag "fix": "To properly set the owner of \"/etc/gshadow\", run the command:

# chown root /etc/gshadow"

  describe file('/etc/gshadow') do
    it { should exist }
  end
  describe file('/etc/gshadow') do
    its('uid') { should cmp 0 }
  end
end
