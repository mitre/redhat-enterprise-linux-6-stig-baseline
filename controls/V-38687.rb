control "V-38687" do
  title "The system must provide VPN connectivity for communications over
untrusted networks."
  desc  "Providing the ability for remote users or systems to initiate a secure
VPN connection protects information when it is transmitted over a wide area
network."
  impact 'low'
  tag "gtitle": "SRG-OS-000160"
  tag "gid": "V-38687"
  tag "rid": "SV-50488r3_rule"
  tag "stig_id": "RHEL-06-000321"
  tag "fix_id": "F-43636r2_fix"
  tag "cci": ["CCI-001130"]
  tag "nist": ["SC-9", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "If the system does not communicate over untrusted networks,
this is not applicable.

Run the following command to determine if the \"libreswan\" package is
installed:

# rpm -q libreswan

If the package is not installed, this is a finding."
  desc 'fix', "The \"libreswan\" package provides an implementation of IPsec and
IKE, which permits the creation of secure tunnels over untrusted networks. The
\"libreswan\" package can be installed with the following command:

# yum install libreswan
"

  describe package("libreswan") do
    it { should be_installed }
  end
end

