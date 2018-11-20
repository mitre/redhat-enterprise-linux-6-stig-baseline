control "V-38555" do
  title "The system must employ a local IPv4 firewall."
  desc  "The \"iptables\" service provides the system's host-based firewalling
capability for IPv4 and ICMP."
  impact 0.5
  tag "gtitle": "SRG-OS-000152"
  tag "gid": "V-38555"
  tag "rid": "SV-50356r2_rule"
  tag "stig_id": "RHEL-06-000113"
  tag "fix_id": "F-43503r2_fix"
  tag "cci": ["CCI-001118"]
  tag "nist": ["SC-7 (12)", "Rev_4"]
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
  tag "check": "If the system is a cross-domain system, this is not applicable.

Run the following command to determine the current status of the \"iptables\"
service:

# service iptables status

If the service is not running, it should return the following:

iptables: Firewall is not running.


If the service is not running, this is a finding."
  tag "fix": "The \"iptables\" service can be enabled with the following
commands:

# chkconfig iptables on
# service iptables start"

  describe service('iptables') do
    it { should be_enabled }
    it { should be_running }
  end
end

