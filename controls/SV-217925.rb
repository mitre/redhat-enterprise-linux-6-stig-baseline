# encoding: UTF-8

control "SV-217925" do
  title "The system must use a reverse-path filter for IPv4 network traffic when possible by default."
  desc "Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks."
  desc "default", "Enabling reverse path filtering drops packets with source addresses
that should not have been able to be received on the interface they were
received on. It should not be used on systems which are routers for complicated
networks, but is helpful for end hosts and routers serving small networks."
  desc "check", "The status of the \"net.ipv4.conf.default.rp_filter\" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.rp_filter
net.ipv4.conf.default.rp_filter = 1

$ grep net.ipv4.conf.default.rp_filter /etc/sysctl.conf /etc/sysctl.d/*
net.ipv4.conf.default.rp_filter = 1

If \"net.ipv4.conf.default.rp_filter\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of \"1\", this is a finding."
  desc "fix", "To set the runtime status of the \"net.ipv4.conf.default.rp_filter\" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.default.rp_filter=1

Set the system to the required kernel parameter by adding the following line to \"/etc/sysctl.conf\" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value): 

net.ipv4.conf.default.rp_filter = 1

Issue the following command to make the changes take effect:

# sysctl --system"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217925"
  tag rid: "SV-217925r603264_rule"
  tag stig_id: "RHEL-06-000097"
  tag fix_id: "F-19404r376791_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe kernel_parameter("net.ipv4.conf.default.rp_filter") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.rp_filter") do
    its("value") { should eq 1 }
  end
  describe file("/etc/sysctl.conf") do
    its("content") { should match(/^[\s]*net.ipv4.conf.default.rp_filter[\s]*=[\s]*1[\s]*$/) }
  end
end