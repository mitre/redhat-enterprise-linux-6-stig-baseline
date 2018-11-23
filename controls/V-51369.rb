control 'V-51369' do
  title "The system must use a Linux Security Module configured to limit the
privileges of system services."
  desc  "Setting the SELinux policy to \"targeted\" or a more specialized
policy ensures the system will confine processes that are likely to be targeted
for exploitation, such as network or system services. "
  impact 0.3
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-51369'
  tag "rid": 'SV-65579r1_rule'
  tag "stig_id": 'RHEL-06-000023'
  tag "fix_id": 'F-56171r1_fix'
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

SELINUXTYPE=targeted

If it does not, this is a finding. "
  tag "fix": "The SELinux \"targeted\" policy is appropriate for
general-purpose desktops and servers, as well as systems in many other roles.
To configure the system to use this policy, add or correct the following line
in \"/etc/selinux/config\":

SELINUXTYPE=targeted

Other policies, such as \"mls\", provide additional security labeling and
greater confinement but are not compatible with many general-purpose use cases.
"

  describe file('/etc/selinux/config') do
    its('content') { should match(/^[\s]*SELINUXTYPE[\s]*=[\s]*([^\s]*)/) }
  end
  file('/etc/selinux/config').content.to_s.scan(/^[\s]*SELINUXTYPE[\s]*=[\s]*([^\s]*)/).flatten.each do |entry|
    describe entry do
      it { should eq 'targeted' }
    end
  end
end
