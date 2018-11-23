control 'V-51363' do
  title "The system must use a Linux Security Module configured to enforce
limits on system services."
  desc  "Setting the SELinux state to enforcing ensures SELinux is able to
confine potentially compromised processes to the security policy, which is
designed to prevent them from causing damage to the system or further elevating
their privileges. "
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-51363'
  tag "rid": 'SV-65573r1_rule'
  tag "stig_id": 'RHEL-06-000020'
  tag "fix_id": 'F-56165r1_fix'
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
  tag "check": "Check the file \"/etc/selinux/config\" and ensure the following
line appears:

SELINUX=enforcing

If SELINUX is not set to enforcing, this is a finding. "
  tag "fix": "The SELinux state should be set to \"enforcing\" at system boot
time. In the file \"/etc/selinux/config\", add or correct the following line to
configure the system to boot into enforcing mode:

SELINUX=enforcing"

  describe file('/etc/selinux/config') do
    its('content') { should match(/^[\s]*SELINUX[\s]*=[\s]*(.*)[\s]*$/) }
  end
  file('/etc/selinux/config').content.to_s.scan(/^[\s]*SELINUX[\s]*=[\s]*(.*)[\s]*$/).flatten.each do |entry|
    describe entry do
      it { should eq 'enforcing' }
    end
  end
end
