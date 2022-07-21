# encoding: UTF-8

control "SV-217875" do
  title "The /etc/gshadow file must be group-owned by root."
  desc "The \"/etc/gshadow\" file contains group password hashes. Protection of this file is critical for system security."
  desc "default", "The \"/etc/gshadow\" file contains group password hashes. Protection
of this file is critical for system security."
  desc "check", "To check the group ownership of \"/etc/gshadow\", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following group-owner. \"root\" 
If it does not, this is a finding."
  desc "fix", "To properly set the group owner of \"/etc/gshadow\", run the command: 

# chgrp root /etc/gshadow"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217875"
  tag rid: "SV-217875r603264_rule"
  tag stig_id: "RHEL-06-000037"
  tag fix_id: "F-19354r376641_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/gshadow") do
    it { should exist }
  end
  describe file("/etc/gshadow") do
    its("gid") { should cmp 0 }
  end
end