control 'V-38523' do
  title "The system must not accept IPv4 source-routed packets on any
interface."
  desc  "Accepting source-routed packets in the IPv4 protocol has few
legitimate uses. It should be disabled unless it is absolutely required."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38523'
  tag "rid": 'SV-50324r2_rule'
  tag "stig_id": 'RHEL-06-000083'
  tag "fix_id": 'F-43471r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "The status of the \"net.ipv4.conf.all.accept_source_route\"
kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.accept_source_route

The output of the command should indicate a value of \"0\". If this value is
not the default value, investigate how it could have been adjusted at runtime,
and verify it is not set improperly in \"/etc/sysctl.conf\".

$ grep net.ipv4.conf.all.accept_source_route /etc/sysctl.conf

If the correct value is not returned, this is a finding. "
  tag "fix": "To set the runtime status of the
\"net.ipv4.conf.all.accept_source_route\" kernel parameter, run the following
command:

# sysctl -w net.ipv4.conf.all.accept_source_route=0

If this is not the system's default value, add the following line to
\"/etc/sysctl.conf\":

net.ipv4.conf.all.accept_source_route = 0"

  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should_not be_nil }
  end
  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end
  describe file('/etc/sysctl.conf') do
    its('content') { should match(/^[\s]*net.ipv4.conf.all.accept_source_route[\s]*=[\s]*0[\s]*$/) }
  end
end
