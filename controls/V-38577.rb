control 'V-38577' do
  title "The system must use a FIPS 140-2 approved cryptographic hashing
algorithm for generating account password hashes (libuser.conf)."
  desc  "Using a stronger hashing algorithm makes password cracking attacks
more difficult."
  impact 0.5
  tag "gtitle": 'SRG-OS-000120'
  tag "gid": 'V-38577'
  tag "rid": 'SV-50378r1_rule'
  tag "stig_id": 'RHEL-06-000064'
  tag "fix_id": 'F-43525r1_fix'
  tag "cci": ['CCI-000803']
  tag "nist": ['IA-7', 'Rev_4']
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
  tag "check": "Inspect \"/etc/libuser.conf\" and ensure the following line
appears in the \"[default]\" section:

crypt_style = sha512


If it does not, this is a finding."
  tag "fix": "In \"/etc/libuser.conf\", add or correct the following line in
its \"[defaults]\" section to ensure the system will use the SHA-512 algorithm
for password hashing:

crypt_style = sha512"

  describe file('/etc/libuser.conf') do
    its('content') { should match(/^[\s]*crypt_style[\s]+=[\s]+(?i)sha512[\s]*$/) }
  end
end
