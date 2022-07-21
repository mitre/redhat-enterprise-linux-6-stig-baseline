# encoding: UTF-8

control "SV-218041" do
  title "The xorg-x11-server-common (X Windows) package must not be installed, unless required."
  desc "Unnecessary packages should not be installed to decrease the attack surface of the system."
  desc "default", "Unnecessary packages should not be installed to decrease the attack
surface of the system."
  desc "check", "To ensure the X Windows package group is removed, run the following command: 

$ rpm -qi xorg-x11-server-common

The output should be: 

package xorg-x11-server-common is not installed


If it is not, this is a finding."
  desc "fix", "Removing all packages which constitute the X Window System ensures users or malicious software cannot start X. To do so, run the following command: 

# yum groupremove \"X Window System\""
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000095"
  tag gid: "V-218041"
  tag rid: "SV-218041r603264_rule"
  tag stig_id: "RHEL-06-000291"
  tag fix_id: "F-19520r377139_fix"
  tag cci: ["CCI-000366", "CCI-000381"]
  tag nist: ["CM-6 b", "Rev_4", "CM-7 a"]

  describe package("xorg-x11-server-common") do
    it { should_not be_installed }
  end
end