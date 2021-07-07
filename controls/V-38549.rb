control "V-38549" do
  title "The system must employ a local IPv6 firewall."
  desc  "The \"ip6tables\" service provides the system's host-based firewalling
capability for IPv6 and ICMPv6."
  impact 'medium'
  tag "gtitle": "SRG-OS-000152"
  tag "gid": "V-38549"
  tag "rid": "SV-50350r3_rule"
  tag "stig_id": "RHEL-06-000103"
  tag "fix_id": "F-43497r3_fix"
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
  desc 'check', "If the system is a cross-domain system, this is not applicable.

If IPv6 is disabled, this is not applicable.

Run the following command to determine the current status of the \"ip6tables\"
service:

# service ip6tables status

If the service is not running, it should return the following:

ip6tables: Firewall is not running.


If the service is not running, this is a finding."
  desc 'fix', "The \"ip6tables\" service can be enabled with the following
commands:

# chkconfig ip6tables on
# service ip6tables start"

  describe service('ip6tables') do
    it { should be_enabled }
    it { should be_running }
  end
end

