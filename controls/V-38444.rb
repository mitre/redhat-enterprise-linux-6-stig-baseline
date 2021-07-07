control "V-38444" do
  title "The systems local IPv6 firewall must implement a deny-all,
allow-by-exception policy for inbound packets."
  desc  "In \"ip6tables\" the default policy is applied only after all the
applicable rules in the table are examined for a match. Setting the default
policy to \"DROP\" implements proper design for a firewall, i.e., any packets
which are not explicitly permitted should not be accepted."
  impact 'medium'
  tag "gtitle": "SRG-OS-000231"
  tag "gid": "V-38444"
  tag "rid": "SV-50244r2_rule"
  tag "stig_id": "RHEL-06-000523"
  tag "fix_id": "F-43389r3_fix"
  tag "cci": ["CCI-000066"]
  tag "nist": ["AC-17 e", "Rev_4"]
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
  desc 'check', "If IPv6 is disabled, this is not applicable.

Inspect the file \"/etc/sysconfig/ip6tables\" to determine the default policy
for the INPUT chain. It should be set to DROP:

# grep \":INPUT\" /etc/sysconfig/ip6tables

If the default policy for the INPUT chain is not set to DROP, this is a
finding. "
  desc 'fix', "To set the default policy to DROP (instead of ACCEPT) for the
built-in INPUT chain which processes incoming packets, add or correct the
following line in \"/etc/sysconfig/ip6tables\":

:INPUT DROP [0:0]

Restart the IPv6 firewall:

# service ip6tables restart"

  describe command("ip6tables -nvL | grep -i input") do
    its('stdout.strip') { should match %r{Chain INPUT \(policy DROP\) } }
  end
end
