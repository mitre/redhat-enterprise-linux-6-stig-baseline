# encoding: UTF-8

control "SV-217880" do
  title "The /etc/group file must be owned by root."
  desc "The \"/etc/group\" file contains information regarding groups that are configured on the system. Protection of this file is important for system security."
  desc "default", "The \"/etc/group\" file contains information regarding groups that are
configured on the system. Protection of this file is important for system
security."
  desc "check", "To check the ownership of \"/etc/group\", run the command: 

$ ls -l /etc/group

If properly configured, the output should indicate the following owner: \"root\" 
If it does not, this is a finding."
  desc "fix", "To properly set the owner of \"/etc/group\", run the command: 

# chown root /etc/group"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217880"
  tag rid: "SV-217880r603264_rule"
  tag stig_id: "RHEL-06-000042"
  tag fix_id: "F-19359r376656_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/group") do
    it { should exist }
  end
  describe file("/etc/group") do
    its("uid") { should cmp 0 }
  end
end