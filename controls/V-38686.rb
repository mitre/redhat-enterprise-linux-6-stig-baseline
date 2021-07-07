control "V-38686" do
  title "The systems local firewall must implement a deny-all,
allow-by-exception policy for forwarded packets."
  desc  "In \"iptables\" the default policy is applied only after all the
applicable rules in the table are examined for a match. Setting the default
policy to \"DROP\" implements proper design for a firewall, i.e., any packets
which are not explicitly permitted should not be accepted."
  impact 'medium'
  tag "gtitle": "SRG-OS-000147"
  tag "gid": "V-38686"
  tag "rid": "SV-50487r2_rule"
  tag "stig_id": "RHEL-06-000320"
  tag "fix_id": "F-43635r1_fix"
  tag "cci": ["CCI-001109"]
  tag "nist": ["SC-7 (5)", "Rev_4"]
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
  desc 'check', "Run the following command to ensure the default \"FORWARD\"
policy is \"DROP\":

# iptables -nvL | grep -i forward

Chain FORWARD (policy DROP 0 packets, 0 bytes)

If the default policy for the FORWARD chain is not set to DROP, this is a
finding."
  desc 'fix', "To set the default policy to DROP (instead of ACCEPT) for the
built-in FORWARD chain which processes packets that will be forwarded from one
interface to another, add or correct the following line in
\"/etc/sysconfig/iptables\":

:FORWARD DROP [0:0]"

  describe command("iptables -nvL | grep -i forward") do
    its('stdout.strip') { should match %r{Chain FORWARD \(policy DROP} }
  end
end

