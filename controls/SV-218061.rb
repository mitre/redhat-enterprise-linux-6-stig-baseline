# encoding: UTF-8

control "SV-218061" do
  title "The system must provide VPN connectivity for communications over untrusted networks."
  desc "Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network."
  desc "default", "Providing the ability for remote users or systems to initiate a secure
VPN connection protects information when it is transmitted over a wide area
network."
  desc "check", "If the system does not communicate over untrusted networks, this is not applicable.

Run the following command to determine if the \"libreswan\" package is installed: 

# rpm -q libreswan

If the package is not installed, this is a finding."
  desc "fix", "The “libreswan” package provides an implementation of IPsec and IKE, which permits the creation of secure tunnels over untrusted networks. The \"libreswan\" package can be installed with the following command: 

# yum install libreswan"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218061"
  tag rid: "SV-218061r603264_rule"
  tag stig_id: "RHEL-06-000321"
  tag fix_id: "F-19540r462413_fix"
  tag cci: ["CCI-001130", "CCI-000366"]
  tag nist: ["SC-9", "Rev_4", "CM-6 b"]

  describe package("libreswan") do
    it { should be_installed }
  end
end