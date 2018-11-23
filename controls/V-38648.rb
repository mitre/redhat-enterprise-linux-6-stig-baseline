control 'V-38648' do
  title 'The qpidd service must not be running.'
  desc  "The qpidd service is automatically installed when the \"base\" package
selection is selected during installation. The qpidd service listens for
network connections which increases the attack surface of the system. If the
system is not intended to receive AMQP traffic then the \"qpidd\" service is
not needed and should be disabled or removed."
  impact 0.3
  tag "gtitle": 'SRG-OS-000096'
  tag "gid": 'V-38648'
  tag "rid": 'SV-50449r2_rule'
  tag "stig_id": 'RHEL-06-000267'
  tag "fix_id": 'F-43597r2_fix'
  tag "cci": ['CCI-000382']
  tag "nist": ['CM-7 b', 'Rev_4']
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
  tag "check": "To check that the \"qpidd\" service is disabled in system boot
configuration, run the following command:

# chkconfig \"qpidd\" --list

Output should indicate the \"qpidd\" service has either not been installed, or
has been disabled at all runlevels, as shown in the example below:

# chkconfig \"qpidd\" --list
\"qpidd\" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"qpidd\" is disabled through current
runtime configuration:

# service qpidd status

If the service is disabled the command will return the following output:

qpidd is stopped


If the service is running, this is a finding."
  tag "fix": "The \"qpidd\" service provides high speed, secure, guaranteed
delivery services. It is an implementation of the Advanced Message Queuing
Protocol. By default the qpidd service will bind to port 5672 and listen for
connection attempts. The \"qpidd\" service can be disabled with the following
commands:

# chkconfig qpidd off
# service qpidd stop"

  describe.one do
    describe package('qpid-cpp-server') do
      it { should_not be_installed }
    end
    describe service('qpidd') do
      its('runlevels(?-mix:0)') { should be_enabled }
      its('runlevels(?-mix:1)') { should be_enabled }
      its('runlevels(?-mix:2)') { should be_enabled }
      its('runlevels(?-mix:3)') { should be_enabled }
      its('runlevels(?-mix:4)') { should be_enabled }
      its('runlevels(?-mix:5)') { should be_enabled }
      its('runlevels(?-mix:6)') { should be_enabled }
    end
  end
end
