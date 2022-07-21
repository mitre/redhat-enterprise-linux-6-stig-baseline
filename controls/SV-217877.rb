# encoding: UTF-8

control "SV-217877" do
  title "The /etc/passwd file must be owned by root."
  desc "The \"/etc/passwd\" file contains information about the users that are configured on the system. Protection of this file is critical for system security."
  desc "default", "The \"/etc/passwd\" file contains information about the users that are
configured on the system. Protection of this file is critical for system
security."
  desc "check", "To check the ownership of \"/etc/passwd\", run the command: 

$ ls -l /etc/passwd

If properly configured, the output should indicate the following owner: \"root\" 
If it does not, this is a finding."
  desc "fix", "To properly set the owner of \"/etc/passwd\", run the command: 

# chown root /etc/passwd"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217877"
  tag rid: "SV-217877r603264_rule"
  tag stig_id: "RHEL-06-000039"
  tag fix_id: "F-19356r376647_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/passwd") do
    it { should exist }
  end
  describe file("/etc/passwd") do
    its("uid") { should cmp 0 }
  end
end