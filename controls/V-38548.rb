control 'V-38548' do
  title 'The system must ignore ICMPv6 redirects by default.'
  desc  "An illicit ICMP redirect message could result in a man-in-the-middle
attack."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38548'
  tag "rid": 'SV-50349r3_rule'
  tag "stig_id": 'RHEL-06-000099'
  tag "fix_id": 'F-43496r1_fix'
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
  tag "check": "If IPv6 is disabled, this is not applicable.

The status of the \"net.ipv6.conf.default.accept_redirects\" kernel parameter
can be queried by running the following command:

$ sysctl net.ipv6.conf.default.accept_redirects

The output of the command should indicate a value of \"0\". If this value is
not the default value, investigate how it could have been adjusted at runtime,
and verify it is not set improperly in \"/etc/sysctl.conf\".

$ grep net.ipv6.conf.default.accept_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding. "
  tag "fix": "To set the runtime status of the
\"net.ipv6.conf.default.accept_redirects\" kernel parameter, run the following
command:

# sysctl -w net.ipv6.conf.default.accept_redirects=0

If this is not the system's default value, add the following line to
\"/etc/sysctl.conf\":

net.ipv6.conf.default.accept_redirects = 0"

  describe kernel_parameter('net.ipv6.conf.default.accept_redirects') do
    its('value') { should eq 0 }
  end
  describe file('/etc/sysctl.conf') do
    its('content') { should match(/^[\s]*net.ipv6.conf.default.accept_redirects[\s]*=[\s]*0[\s]*$/) }
  end
end
