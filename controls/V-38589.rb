control 'V-38589' do
  title 'The telnet daemon must not be running.'
  desc  "The telnet protocol uses unencrypted network communication, which
means that data from the login session, including passwords and all other
information transmitted during the session, can be stolen by eavesdroppers on
the network. The telnet protocol is also subject to man-in-the-middle attacks.

    Mitigation:  If an enabled telnet daemon is configured to only allow
encrypted sessions, such as with Kerberos or the use of encrypted network
tunnels, the risk of exposing sensitive information is mitigated.
  "
  impact 0.7
  tag "gtitle": 'SRG-OS-000129'
  tag "gid": 'V-38589'
  tag "rid": 'SV-50390r2_rule'
  tag "stig_id": 'RHEL-06-000211'
  tag "fix_id": 'F-43537r1_fix'
  tag "cci": ['CCI-000888']
  tag "nist": ['MA-4 (6)', 'Rev_4']
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
  tag "check": "To check that the \"telnet\" service is disabled in system boot
configuration, run the following command:

# chkconfig \"telnet\" --list

Output should indicate the \"telnet\" service has either not been installed, or
has been disabled, as shown in the example below:

# chkconfig \"telnet\" --list
telnet         off
OR
error reading information on service telnet: No such file or directory


If the service is running, this is a finding."
  tag "fix": "The \"telnet\" service can be disabled with the following
command:

# chkconfig telnet off"

  describe.one do
    describe package('telnet-server') do
      it { should_not be_installed }
    end
    describe file('/etc/xinetd.d/telnet') do
      its('content') { should match(/^\s*disable\s+=\s+yes\s*$/) }
    end
  end
end
