control 'V-38512' do
  title "The operating system must prevent public IPv4 access into an
organizations internal networks, except as appropriately mediated by managed
interfaces employing boundary protection devices."
  desc  "The \"iptables\" service provides the system's host-based firewalling
capability for IPv4 and ICMP."
  impact 0.5
  tag "gtitle": 'SRG-OS-000146'
  tag "gid": 'V-38512'
  tag "rid": 'SV-50313r2_rule'
  tag "stig_id": 'RHEL-06-000117'
  tag "fix_id": 'F-43459r2_fix'
  tag "cci": ['CCI-001100']
  tag "nist": ['SC-7 (2)', 'Rev_4']
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
