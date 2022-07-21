# encoding: UTF-8

control "SV-217876" do
  title "The /etc/gshadow file must have mode 0000."
  desc "The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security."
  desc "default", "The /etc/gshadow file contains group password hashes. Protection of
this file is critical for system security."
  desc "check", "To check the permissions of \"/etc/gshadow\", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following permissions: \"----------\" 
If it does not, this is a finding."
  desc "fix", "To properly set the permissions of \"/etc/gshadow\", run the command: 

# chmod 0000 /etc/gshadow"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217876"
  tag rid: "SV-217876r603264_rule"
  tag stig_id: "RHEL-06-000038"
  tag fix_id: "F-19355r376644_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/gshadow") do
    it { should exist }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/gshadow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_setgid }
  end
  describe file("/etc/gshadow") do
    it { should_not be_sticky }
  end
  describe file("/etc/gshadow") do
    it { should_not be_setuid }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "owner" }
  end
  describe file("/etc/gshadow") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "owner" }
  end
end