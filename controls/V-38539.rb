control 'V-38539' do
  title "The system must be configured to use TCP syncookies when experiencing
a TCP SYN flood."
  desc  "A TCP SYN flood attack can cause a denial of service by filling a
system's TCP connection table with connections in the SYN_RCVD state.
Syncookies can be used to track a connection when a subsequent ACK is received,
verifying the initiator is attempting a valid connection and is not a flood
source. This feature is activated when a flood condition is detected, and
enables the system to continue servicing valid connection requests."
  impact 0.5
  tag "gtitle": 'SRG-OS-000142'
  tag "gid": 'V-38539'
  tag "rid": 'SV-50340r2_rule'
  tag "stig_id": 'RHEL-06-000095'
  tag "fix_id": 'F-43487r1_fix'
  tag "cci": ['CCI-001095']
  tag "nist": ['SC-5 (2)', 'Rev_4']
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
  tag "check": "The status of the \"net.ipv4.tcp_syncookies\" kernel parameter
can be queried by running the following command:

$ sysctl net.ipv4.tcp_syncookies

The output of the command should indicate a value of \"1\". If this value is
not the default value, investigate how it could have been adjusted at runtime,
and verify it is not set improperly in \"/etc/sysctl.conf\".

$ grep net.ipv4.tcp_syncookies /etc/sysctl.conf

If the correct value is not returned, this is a finding. "
  tag "fix": "To set the runtime status of the \"net.ipv4.tcp_syncookies\"
kernel parameter, run the following command:

# sysctl -w net.ipv4.tcp_syncookies=1

If this is not the system's default value, add the following line to
\"/etc/sysctl.conf\":

net.ipv4.tcp_syncookies = 1"

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should_not be_nil }
  end
  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq 1 }
  end
  describe file('/etc/sysctl.conf') do
    its('content') { should match(/^[\s]*net.ipv4.tcp_syncookies[\s]*=[\s]*1[\s]*$/) }
  end
end
