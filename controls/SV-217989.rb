# encoding: UTF-8

control "SV-217989" do
  title "The ypserv package must not be installed."
  desc "Removing the \"ypserv\" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services."
  desc "default", "Removing the \"ypserv\" package decreases the risk of the accidental
(or intentional) activation of NIS or NIS+ services."
  desc "check", "Run the following command to determine if the \"ypserv\" package is installed: 

# rpm -q ypserv


If the package is installed, this is a finding."
  desc "fix", "The \"ypserv\" package can be uninstalled with the following command: 

# yum erase ypserv"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000095"
  tag gid: "V-217989"
  tag rid: "SV-217989r603264_rule"
  tag stig_id: "RHEL-06-000220"
  tag fix_id: "F-19468r376983_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  describe package("ypserv") do
    it { should_not be_installed }
  end
end