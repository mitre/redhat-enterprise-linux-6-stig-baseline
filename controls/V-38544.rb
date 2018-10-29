control "V-38544" do
  title "The system must use a reverse-path filter for IPv4 network traffic
when possible by default."
  desc  "Enabling reverse path filtering drops packets with source addresses
that should not have been able to be received on the interface they were
received on. It should not be used on systems which are routers for complicated
networks, but is helpful for end hosts and routers serving small networks."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38544"
  tag "rid": "SV-50345r2_rule"
  tag "stig_id": "RHEL-06-000097"
  tag "fix_id": "F-43492r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "The status of the \"net.ipv4.conf.default.rp_filter\" kernel
parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.rp_filter

The output of the command should indicate a value of \"1\". If this value is
not the default value, investigate how it could have been adjusted at runtime,
and verify it is not set improperly in \"/etc/sysctl.conf\".

$ grep net.ipv4.conf.default.rp_filter /etc/sysctl.conf

If the correct value is not returned, this is a finding. "
  tag "fix": "To set the runtime status of the
\"net.ipv4.conf.default.rp_filter\" kernel parameter, run the following
command:

# sysctl -w net.ipv4.conf.default.rp_filter=1

If this is not the system's default value, add the following line to
\"/etc/sysctl.conf\":

net.ipv4.conf.default.rp_filter = 1"

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

