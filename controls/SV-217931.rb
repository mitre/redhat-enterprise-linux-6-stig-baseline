# encoding: UTF-8

control "SV-217931" do
  title "The operating system must connect to external networks or information systems only through managed IPv4 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture."
  desc "The \"iptables\" service provides the system's host-based firewalling capability for IPv4 and ICMP."
  desc "default", "The \"iptables\" service provides the system's host-based firewalling
capability for IPv4 and ICMP."
  desc "check", "If the system is a cross-domain system, this is not applicable.

Run the following command to determine the current status of the \"iptables\" service: 

# service iptables status

If the service is not running, it should return the following: 

iptables: Firewall is not running.


If the service is not running, this is a finding."
  desc "fix", "The \"iptables\" service can be enabled with the following commands: 

# chkconfig iptables on
# service iptables start"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217931"
  tag rid: "SV-217931r603264_rule"
  tag stig_id: "RHEL-06-000116"
  tag fix_id: "F-19410r376809_fix"
  tag cci: ["CCI-001098", "CCI-000366"]
  tag nist: ["SC-7 c", "Rev_4", "CM-6 b"]

  describe service('iptables') do
    it { should be_enabled }
    it { should be_running }
  end
end