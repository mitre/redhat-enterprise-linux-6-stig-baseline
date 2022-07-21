# encoding: UTF-8

control "SV-217999" do
  title "The SSH daemon must not allow host-based authentication."
  desc "SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts."
  desc "default", "SSH trust relationships mean a compromise on one host can allow an
attacker to move trivially to other hosts."
  desc "check", "To determine how the SSH daemon's \"HostbasedAuthentication\" option is set, run the following command: 

# grep -i HostbasedAuthentication /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value \"no\" is returned, then the required value is set. 
If the required value is not set, this is a finding."
  desc "fix", "SSH's cryptographic host-based authentication is more secure than \".rhosts\" authentication, since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization. 

To disable host-based authentication, add or correct the following line in \"/etc/ssh/sshd_config\": 

HostbasedAuthentication no"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000106"
  tag gid: "V-217999"
  tag rid: "SV-217999r603264_rule"
  tag stig_id: "RHEL-06-000236"
  tag fix_id: "F-19478r377013_fix"
  tag cci: ["CCI-000766"]
  tag nist: ["IA-2 (2)", "Rev_4"]

  describe sshd_config do
    its('HostbasedAuthentication') { should (eq 'no').or be_nil }
  end
end