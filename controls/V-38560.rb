control "V-38560" do
  title "The operating system must connect to external networks or information
systems only through managed IPv4 interfaces consisting of boundary protection
devices arranged in accordance with an organizational security architecture."
  desc  "The \"iptables\" service provides the system's host-based firewalling
capability for IPv4 and ICMP."
  impact 'medium'
  tag "gtitle": "SRG-OS-000145"
  tag "gid": "V-38560"
  tag "rid": "SV-50361r2_rule"
  tag "stig_id": "RHEL-06-000116"
  tag "fix_id": "F-43508r2_fix"
  tag "cci": ["CCI-001098"]
  tag "nist": ["SC-7 c", "Rev_4"]
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
  desc 'check', "If the system is a cross-domain system, this is not applicable.

Run the following command to determine the current status of the \"iptables\"
service:

# service iptables status

If the service is not running, it should return the following:

iptables: Firewall is not running.


If the service is not running, this is a finding."
  desc 'fix', "The \"iptables\" service can be enabled with the following
commands:

# chkconfig iptables on
# service iptables start"

  describe service('iptables') do
    it { should be_enabled }
    it { should be_running }
  end
end

