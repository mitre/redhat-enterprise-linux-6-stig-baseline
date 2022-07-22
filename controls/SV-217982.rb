# encoding: UTF-8

control "SV-217982" do
  title "The xinetd service must be uninstalled if no network services utilizing it are enabled."
  desc "Removing the \"xinetd\" package decreases the risk of the xinetd service's accidental (or intentional) activation."
  desc "default", "Removing the \"xinetd\" package decreases the risk of the xinetd
service's accidental (or intentional) activation."
  desc "check", "If network services are using the xinetd service, this is not applicable.

Run the following command to determine if the \"xinetd\" package is installed: 

# rpm -q xinetd


If the package is installed, this is a finding."
  desc "fix", "The \"xinetd\" package can be uninstalled with the following command: 

# yum erase xinetd"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000096"
  tag gid: "V-217982"
  tag rid: "SV-217982r603264_rule"
  tag stig_id: "RHEL-06-000204"
  tag fix_id: "F-19461r376962_fix"
  tag cci: ["CCI-000382"]
  tag nist: ["CM-7 b", "Rev_4"]

  describe package("xinetd") do
    it { should_not be_installed }
  end
end