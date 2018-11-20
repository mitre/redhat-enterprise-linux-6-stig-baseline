control "V-38551" do
  title "The operating system must connect to external networks or information
systems only through managed IPv6 interfaces consisting of boundary protection
devices arranged in accordance with an organizational security architecture."
  desc  "The \"ip6tables\" service provides the system's host-based firewalling
capability for IPv6 and ICMPv6."
  impact 0.5
  tag "gtitle": "SRG-OS-000145"
  tag "gid": "V-38551"
  tag "rid": "SV-50352r3_rule"
  tag "stig_id": "RHEL-06-000106"
  tag "fix_id": "F-43499r2_fix"
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
  tag "check": "If the system is a cross-domain system, this is not applicable.

If IPV6 is disabled, this is not applicable.

Run the following command to determine the current status of the \"ip6tables\"
service:

# service ip6tables status

If the service is not running, it should return the following:

ip6tables: Firewall is not running.


If the service is not running, this is a finding."
  tag "fix": "The \"ip6tables\" service can be enabled with the following
commands:

# chkconfig ip6tables on
# service ip6tables start"

  describe service('ip6tables') do
    it { should be_enabled }
    it { should be_running }
  end
end

