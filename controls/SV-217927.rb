# encoding: UTF-8

control "SV-217927" do
  title "The system must employ a local IPv6 firewall."
  desc "The \"ip6tables\" service provides the system's host-based firewalling capability for IPv6 and ICMPv6."
  desc "default", "The \"ip6tables\" service provides the system's host-based firewalling
capability for IPv6 and ICMPv6."
  desc "check", "If the system is a cross-domain system, this is not applicable.

If IPv6 is disabled, this is not applicable.

Run the following command to determine the current status of the \"ip6tables\" service: 

# service ip6tables status

If the service is not running, it should return the following: 

ip6tables: Firewall is not running.


If the service is not running, this is a finding."
  desc "fix", "The \"ip6tables\" service can be enabled with the following commands: 

# chkconfig ip6tables on
# service ip6tables start"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217927"
  tag rid: "SV-217927r603264_rule"
  tag stig_id: "RHEL-06-000103"
  tag fix_id: "F-19406r376797_fix"
  tag cci: ["CCI-001118", "CCI-000366"]
  tag nist: ["SC-7 (12)", "Rev_4", "CM-6 b"]

  describe service('ip6tables') do
    it { should be_enabled }
    it { should be_running }
  end
end