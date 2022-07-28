# encoding: UTF-8

control "SV-217914" do
  title "The system must not accept IPv4 source-routed packets on any interface."
  desc "Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required."
  desc "default", "Accepting source-routed packets in the IPv4 protocol has few
legitimate uses. It should be disabled unless it is absolutely required."
  desc "check", "The status of the \"net.ipv4.conf.all.accept_source_route\" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.accept_source_route
net.ipv4.conf.all.accept_source_route = 0

$ grep net.ipv4.conf.all.accept_source_route /etc/sysctl.conf /etc/sysctl.d/*
net.ipv4.conf.all.accept_source_route = 0

If \"net.ipv4.conf.all.accept_source_route\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of \"0\", this is a finding."
  desc "fix", "To set the runtime status of the \"net.ipv4.conf.all.accept_source_route\" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.accept_source_route=0

Set the system to the required kernel parameter by adding the following line to \"/etc/sysctl.conf\" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value):  

net.ipv4.conf.all.accept_source_route = 0

Issue the following command to make the changes take effect:

# sysctl --system"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217914"
  tag rid: "SV-217914r603264_rule"
  tag stig_id: "RHEL-06-000083"
  tag fix_id: "F-19393r376758_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should eq 0 }
  end
  describe file("/etc/sysctl.conf") do
    its("content") { should match(/^[\s]*net.ipv4.conf.all.accept_source_route[\s]*=[\s]*0[\s]*$/) }
  end
end