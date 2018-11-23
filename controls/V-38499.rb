control 'V-38499' do
  title 'The /etc/passwd file must not contain password hashes.'
  desc  "The hashes for all user account passwords should be stored in the file
\"/etc/shadow\" and never in \"/etc/passwd\", which is readable by all users."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38499'
  tag "rid": 'SV-50300r1_rule'
  tag "stig_id": 'RHEL-06-000031'
  tag "fix_id": 'F-43446r1_fix'
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
  tag "check": "To check that no password hashes are stored in \"/etc/passwd\",
run the following command:

# awk -F: '($2 != \"x\") {print}' /etc/passwd

If it produces any output, then a password hash is stored in \"/etc/passwd\".
If any stored hashes are found in /etc/passwd, this is a finding."
  tag "fix": "If any password hashes are stored in \"/etc/passwd\" (in the
second field, instead of an \"x\"), the cause of this misconfiguration should
be investigated. The account should have its password reset and the hash should
be properly stored, or the account should be deleted entirely."

  describe file('/etc/passwd') do
    its('content') { should match(/^[^:]*:([^:]*):/) }
  end
  file('/etc/passwd').content.to_s.scan(/^[^:]*:([^:]*):/).flatten.each do |entry|
    describe entry do
      it { should eq 'x' }
    end
  end
end
