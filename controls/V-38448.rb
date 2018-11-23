control 'V-38448' do
  title 'The /etc/gshadow file must be group-owned by root.'
  desc  "The \"/etc/gshadow\" file contains group password hashes. Protection
of this file is critical for system security."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38448'
  tag "rid": 'SV-50248r1_rule'
  tag "stig_id": 'RHEL-06-000037'
  tag "fix_id": 'F-43393r1_fix'
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
  tag "check": "To check the group ownership of \"/etc/gshadow\", run the
command:

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following group-owner.
\"root\"
If it does not, this is a finding."
  tag "fix": "To properly set the group owner of \"/etc/gshadow\", run the
command:

# chgrp root /etc/gshadow"

  describe file('/etc/gshadow') do
    it { should exist }
  end
  describe file('/etc/gshadow') do
    its('gid') { should cmp 0 }
  end
end
