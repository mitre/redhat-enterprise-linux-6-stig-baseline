# encoding: UTF-8

control "SV-218020" do
  title "The rdisc service must not be running."
  desc "General-purpose systems typically have their network and routing information configured statically by a system administrator. Workstations or some special-purpose systems often use DHCP (instead of IRDP) to retrieve dynamic network configuration information."
  desc "default", "General-purpose systems typically have their network and routing
information configured statically by a system administrator. Workstations or
some special-purpose systems often use DHCP (instead of IRDP) to retrieve
dynamic network configuration information."
  desc "check", "To check that the \"rdisc\" service is disabled in system boot configuration, run the following command: 

# chkconfig \"rdisc\" --list

Output should indicate the \"rdisc\" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig \"rdisc\" --list
\"rdisc\" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"rdisc\" is disabled through current runtime configuration: 

# service rdisc status

If the service is disabled the command will return the following output: 

rdisc is stopped


If the service is running, this is a finding."
  desc "fix", "The \"rdisc\" service implements the client side of the ICMP Internet Router Discovery Protocol (IRDP), which allows discovery of routers on the local subnet. If a router is discovered then the local routing table is updated with a corresponding default route. By default this daemon is disabled. The \"rdisc\" service can be disabled with the following commands: 

# chkconfig rdisc off
# service rdisc stop"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000096"
  tag gid: "V-218020"
  tag rid: "SV-218020r603264_rule"
  tag stig_id: "RHEL-06-000268"
  tag fix_id: "F-19499r377076_fix"
  tag cci: ["CCI-000382"]
  tag nist: ["CM-7 b", "Rev_4"]

  describe.one do
    describe package("iputils") do
      it { should_not be_installed }
    end
    describe service("rdisc") do
      its("runlevels(?-mix:0)") { should be_enabled }
      its("runlevels(?-mix:1)") { should be_enabled }
      its("runlevels(?-mix:2)") { should be_enabled }
      its("runlevels(?-mix:3)") { should be_enabled }
      its("runlevels(?-mix:4)") { should be_enabled }
      its("runlevels(?-mix:5)") { should be_enabled }
      its("runlevels(?-mix:6)") { should be_enabled }
    end
  end
end