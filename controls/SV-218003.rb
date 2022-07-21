# encoding: UTF-8

control "SV-218003" do
  title "The SSH daemon must not permit user environment settings."
  desc "SSH environment options potentially allow users to bypass access restriction in some configurations."
  desc "default", "SSH environment options potentially allow users to bypass access
restriction in some configurations."
  desc "check", "To ensure users are not able to present environment daemons, run the following command: 

# grep PermitUserEnvironment /etc/ssh/sshd_config

If properly configured, output should be: 

PermitUserEnvironment no


If it is not, this is a finding."
  desc "fix", "To ensure users are not able to present environment options to the SSH daemon, add or correct the following line in \"/etc/ssh/sshd_config\": 

PermitUserEnvironment no"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000242"
  tag gid: "V-218003"
  tag rid: "SV-218003r603264_rule"
  tag stig_id: "RHEL-06-000241"
  tag fix_id: "F-19482r377025_fix"
  tag cci: ["CCI-001414"]
  tag nist: ["AC-4", "Rev_4"]

  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end