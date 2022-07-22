# encoding: UTF-8

control "SV-218102" do
  title "The systems local IPv6 firewall must implement a deny-all, allow-by-exception policy for inbound packets."
  desc "In \"ip6tables\" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to \"DROP\" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted."
  desc "default", "In \"ip6tables\" the default policy is applied only after all the
applicable rules in the table are examined for a match. Setting the default
policy to \"DROP\" implements proper design for a firewall, i.e., any packets
which are not explicitly permitted should not be accepted."
  desc "check", "If IPv6 is disabled, this is not applicable.

Inspect the file \"/etc/sysconfig/ip6tables\" to determine the default policy for the INPUT chain. It should be set to DROP:

# grep \":INPUT\" /etc/sysconfig/ip6tables

If the default policy for the INPUT chain is not set to DROP, this is a finding."
  desc "fix", "To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in \"/etc/sysconfig/ip6tables\": 

:INPUT DROP [0:0]

Restart the IPv6 firewall:

# service ip6tables restart"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218102"
  tag rid: "SV-218102r603264_rule"
  tag stig_id: "RHEL-06-000523"
  tag fix_id: "F-19581r377322_fix"
  tag cci: ["CCI-000066", "CCI-000366"]
  tag nist: ["AC-17 e", "Rev_4", "CM-6 b"]

  describe command("ip6tables -nvL | grep -i input") do
    its('stdout.strip') { should match %r{Chain INPUT \(policy DROP\) } }
  end
end