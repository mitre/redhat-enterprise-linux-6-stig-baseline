# encoding: UTF-8

control "SV-218042" do
  title "The DHCP client must be disabled if not needed."
  desc "DHCP relies on trusting the local network. If the local network is not trusted, then it should not be used. However, the automatic configuration provided by DHCP is commonly used and the alternative, manual configuration, presents an unacceptable burden in many circumstances."
  desc "default", "DHCP relies on trusting the local network. If the local network is not
trusted, then it should not be used. However, the automatic configuration
provided by DHCP is commonly used and the alternative, manual configuration,
presents an unacceptable burden in many circumstances."
  desc "check", "IIf DHCP is required by the organization, this is Not Applicable.

For each interface [IFACE] on the system (e.g. eth0), verify that DHCP is not being used:

Note: This requirement does not apply to the local loopback interface.

# cat /etc/sysconfig/network-scripts/ifcfg-[IFACE] | grep -i “bootproto” | grep –v “#”

BOOTPROTO=none

If no output is returned this is a finding.

If BOOTPROTO is not set to ”none”, this is a finding."
  desc "fix", "For each interface [IFACE] on the system (e.g. eth0), edit \"/etc/sysconfig/network-scripts/ifcfg-[IFACE]\" and make the following changes. 

Correct the BOOTPROTO line to read:

BOOTPROTO=none


Add or correct the following lines, substituting the appropriate values based on your site's addressing scheme:

NETMASK=[local LAN netmask]
IPADDR=[assigned IP address]
GATEWAY=[local LAN default gateway]"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000095"
  tag gid: "V-218042"
  tag rid: "SV-218042r603264_rule"
  tag stig_id: "RHEL-06-000292"
  tag fix_id: "F-19521r462410_fix"
  tag cci: ["CCI-000366", "CCI-000381"]
  tag nist: ["CM-6 b", "Rev_4", "CM-7 a"]

  command("find /etc/sysconfig/network-scripts -type f -regex .\\*/ifcfg-.\\*").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should match(/^[\s]*BOOTPROTO[\s]*=[\s"]*([^#"\s]*)/) }
    end
  end
end