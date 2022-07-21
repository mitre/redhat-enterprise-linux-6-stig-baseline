# encoding: UTF-8

control "SV-217882" do
  title "The /etc/group file must have mode 0644 or less permissive."
  desc "The \"/etc/group\" file contains information regarding groups that are configured on the system. Protection of this file is important for system security."
  desc "default", "The \"/etc/group\" file contains information regarding groups that are
configured on the system. Protection of this file is important for system
security."
  desc "check", "To check the permissions of \"/etc/group\", run the command: 

$ ls -l /etc/group

If properly configured, the output should indicate the following permissions: \"-rw-r--r--\" 
If it does not, this is a finding."
  desc "fix", "To properly set the permissions of \"/etc/group\", run the command: 

# chmod 644 /etc/group"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217882"
  tag rid: "SV-217882r603264_rule"
  tag stig_id: "RHEL-06-000044"
  tag fix_id: "F-19361r376662_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/group") do
    it { should exist }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_writable.by "owner" }
  end
end