# encoding: UTF-8

control "SV-217932" do
  title "The operating system must prevent public IPv4 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices."
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
  tag gid: "V-217932"
  tag rid: "SV-217932r603264_rule"
  tag stig_id: "RHEL-06-000117"
  tag fix_id: "F-19411r376812_fix"
  tag cci: ["CCI-001100", "CCI-000366"]
  tag nist: ["SC-7 (2)", "Rev_4", "CM-6 b"]

  describe service('iptables') do
    it { should be_enabled }
    it { should be_running }
  end
end