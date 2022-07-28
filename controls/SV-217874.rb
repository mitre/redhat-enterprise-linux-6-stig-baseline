# encoding: UTF-8

control "SV-217874" do
  title "The /etc/gshadow file must be owned by root."
  desc "The \"/etc/gshadow\" file contains group password hashes. Protection of this file is critical for system security."
  desc "default", "The \"/etc/gshadow\" file contains group password hashes. Protection
of this file is critical for system security."
  desc "check", "To check the ownership of \"/etc/gshadow\", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following owner: \"root\" 
If it does not, this is a finding."
  desc "fix", "To properly set the owner of \"/etc/gshadow\", run the command: 

# chown root /etc/gshadow"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217874"
  tag rid: "SV-217874r603264_rule"
  tag stig_id: "RHEL-06-000036"
  tag fix_id: "F-19353r376638_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/gshadow") do
    it { should exist }
  end
  describe file("/etc/gshadow") do
    its("uid") { should cmp 0 }
  end
end