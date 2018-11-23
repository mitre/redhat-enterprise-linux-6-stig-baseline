control 'V-38513' do
  title "The systems local IPv4 firewall must implement a deny-all,
allow-by-exception policy for inbound packets."
  desc  "In \"iptables\" the default policy is applied only after all the
applicable rules in the table are examined for a match. Setting the default
policy to \"DROP\" implements proper design for a firewall, i.e., any packets
which are not explicitly permitted should not be accepted."
  impact 0.5
  tag "gtitle": 'SRG-OS-000231'
  tag "gid": 'V-38513'
  tag "rid": 'SV-50314r2_rule'
  tag "stig_id": 'RHEL-06-000120'
  tag "fix_id": 'F-43460r1_fix'
  tag "cci": ['CCI-000066']
  tag "nist": ['AC-17 e', 'Rev_4']
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
  tag "check": "Run the following command to ensure the default \"INPUT\"
policy is \"DROP\":

# iptables -nvL | grep -i input

Chain INPUT (policy DROP 0 packets, 0 bytes)

If the default policy for the INPUT chain is not set to DROP, this is a
finding."
  tag "fix": "To set the default policy to DROP (instead of ACCEPT) for the
built-in INPUT chain which processes incoming packets, add or correct the
following line in \"/etc/sysconfig/iptables\":

:INPUT DROP [0:0]"

  describe command('iptables -nvL | grep -i input') do
    its('stdout.strip') { should match /Chain INPUT \(policy DROP/ }
  end
end
