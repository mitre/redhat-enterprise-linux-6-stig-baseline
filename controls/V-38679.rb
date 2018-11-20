control "V-38679" do
  title "The DHCP client must be disabled if not needed."
  desc  "DHCP relies on trusting the local network. If the local network is not
trusted, then it should not be used. However, the automatic configuration
provided by DHCP is commonly used and the alternative, manual configuration,
presents an unacceptable burden in many circumstances."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38679"
  tag "rid": "SV-50480r3_rule"
  tag "stig_id": "RHEL-06-000292"
  tag "fix_id": "F-43628r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "If DHCP is required by the organization, this is Not Applicable.

For each interface [IFACE] on the system (e.g. eth0), verify that DHCP is not
being used:

# cat /etc/sysconfig/network-scripts/ifcfg-[IFACE] | grep -i \"bootproto\" | grep
–v \"#\"

BOOTPROTO=none

If no output is returned this is a finding.
If BOOTPROTO is not set to \"none\", this is a finding.
"
  tag "fix": "For each interface [IFACE] on the system (e.g. eth0), edit
\"/etc/sysconfig/network-scripts/ifcfg-[IFACE]\" and make the following
changes.

Correct the BOOTPROTO line to read:

BOOTPROTO=none


Add or correct the following lines, substituting the appropriate values based
on your site's addressing scheme:

NETMASK=[local LAN netmask]
IPADDR=[assigned IP address]
GATEWAY=[local LAN default gateway]"

  command("find /etc/sysconfig/network-scripts -type f -regex .\\*/ifcfg-.\\*").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should match(/^[\s]*BOOTPROTO[\s]*=[\s"]*([^#"\s]*)/) }
    end
  end
end

