control 'V-38617' do
  title "The SSH daemon must be configured to use only FIPS 140-2 approved
ciphers."
  desc  "Approved algorithms should impart some level of confidence in their
implementation. These are also required for compliance."
  impact 0.5
  tag "gtitle": 'SRG-OS-000169'
  tag "gid": 'V-38617'
  tag "rid": 'SV-50418r1_rule'
  tag "stig_id": 'RHEL-06-000243'
  tag "fix_id": 'F-43566r1_fix'
  tag "cci": ['CCI-001144']
  tag "nist": ['SC-13', 'Rev_4']
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
  tag "check": "Only FIPS-approved ciphers should be used. To verify that only
FIPS-approved ciphers are in use, run the following command:

# grep Ciphers /etc/ssh/sshd_config

The output should contain only those ciphers which are FIPS-approved, namely,
the AES and 3DES ciphers.
If that is not the case, this is a finding."
  tag "fix": "Limit the ciphers to those algorithms which are FIPS-approved.
Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. The
following line in \"/etc/ssh/sshd_config\" demonstrates use of FIPS-approved
ciphers:

Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc

The man page \"sshd_config(5)\" contains a list of supported ciphers."

  describe sshd_config do
    its('Ciphers') { should_not be_nil }
  end

  ciphers = sshd_config.params['ciphers']
  unless ciphers.nil?
    describe 'sshd_config Ciphers' do
      subject { sshd_config.params['ciphers'].join(',').split(',') }
      it { should all match /aes|3des/ }
    end
  end
end
