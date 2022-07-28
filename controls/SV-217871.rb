# encoding: UTF-8

control "SV-217871" do
  title "The /etc/shadow file must be owned by root."
  desc "The \"/etc/shadow\" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture."
  desc "default", "The \"/etc/shadow\" file contains the list of local system accounts
and stores password hashes. Protection of this file is critical for system
security. Failure to give ownership of this file to root provides the
designated owner with access to sensitive information which could weaken the
system security posture."
  desc "check", "To check the ownership of \"/etc/shadow\", run the command: 

$ ls -l /etc/shadow

If properly configured, the output should indicate the following owner: \"root\" 
If it does not, this is a finding."
  desc "fix", "To properly set the owner of \"/etc/shadow\", run the command: 

# chown root /etc/shadow"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217871"
  tag rid: "SV-217871r603264_rule"
  tag stig_id: "RHEL-06-000033"
  tag fix_id: "F-19350r376629_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/shadow") do
    it { should exist }
  end
  describe file("/etc/shadow") do
    its("uid") { should cmp 0 }
  end
end