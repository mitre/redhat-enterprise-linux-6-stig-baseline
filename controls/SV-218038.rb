# encoding: UTF-8

control "SV-218038" do
  title "The sendmail package must be removed."
  desc "The sendmail software was not developed with security in mind and its design prevents it from being effectively contained by SELinux. Postfix should be used instead."
  desc "default", "The sendmail software was not developed with security in mind and its
design prevents it from being effectively contained by SELinux. Postfix should
be used instead."
  desc "check", "Run the following command to determine if the \"sendmail\" package is installed: 

# rpm -q sendmail


If the package is installed, this is a finding."
  desc "fix", "Sendmail is not the default mail transfer agent and is not installed by default. The \"sendmail\" package can be removed with the following command: 

# yum erase sendmail"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000095"
  tag gid: "V-218038"
  tag rid: "SV-218038r603264_rule"
  tag stig_id: "RHEL-06-000288"
  tag fix_id: "F-19517r377130_fix"
  tag cci: ["CCI-000366", "CCI-000381"]
  tag nist: ["CM-6 b", "Rev_4", "CM-7 a"]

  describe package("sendmail") do
    it { should_not be_installed }
  end
end