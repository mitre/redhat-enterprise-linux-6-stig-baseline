# encoding: UTF-8

control "SV-218060" do
  title "The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets."
  desc "In \"iptables\" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to \"DROP\" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted."
  desc "default", "In \"iptables\" the default policy is applied only after all the
applicable rules in the table are examined for a match. Setting the default
policy to \"DROP\" implements proper design for a firewall, i.e., any packets
which are not explicitly permitted should not be accepted."
  desc "check", "Run the following command to ensure the default \"FORWARD\" policy is \"DROP\": 

# iptables -nvL | grep -i forward

Chain FORWARD (policy DROP 0 packets, 0 bytes)

If the default policy for the FORWARD chain is not set to DROP, this is a finding."
  desc "fix", "To set the default policy to DROP (instead of ACCEPT) for the built-in FORWARD chain which processes packets that will be forwarded from one interface to another, add or correct the following line in \"/etc/sysconfig/iptables\": 

:FORWARD DROP [0:0]"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218060"
  tag rid: "SV-218060r603264_rule"
  tag stig_id: "RHEL-06-000320"
  tag fix_id: "F-19539r377196_fix"
  tag cci: ["CCI-001109", "CCI-000366"]
  tag nist: ["SC-7 (5)", "Rev_4", "CM-6 b"]

  describe command("iptables -nvL | grep -i forward") do
    its('stdout.strip') { should match %r{Chain FORWARD \(policy DROP} }
  end
end