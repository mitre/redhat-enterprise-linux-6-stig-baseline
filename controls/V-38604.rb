control 'V-38604' do
  title 'The ypbind service must not be running.'
  desc  "Disabling the \"ypbind\" service ensures the system is not acting as a
client in a NIS or NIS+ domain."
  impact 0.5
  tag "gtitle": 'SRG-OS-000096'
  tag "gid": 'V-38604'
  tag "rid": 'SV-50405r2_rule'
  tag "stig_id": 'RHEL-06-000221'
  tag "fix_id": 'F-43552r2_fix'
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
  tag "check": "To check that the \"ypbind\" service is disabled in system boot
configuration, run the following command:

# chkconfig \"ypbind\" --list

Output should indicate the \"ypbind\" service has either not been installed, or
has been disabled at all runlevels, as shown in the example below:

# chkconfig \"ypbind\" --list
\"ypbind\" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"ypbind\" is disabled through current
runtime configuration:

# service ypbind status

If the service is disabled the command will return the following output:

ypbind is stopped


If the service is running, this is a finding."
  tag "fix": "The \"ypbind\" service, which allows the system to act as a
client in a NIS or NIS+ domain, should be disabled. The \"ypbind\" service can
be disabled with the following commands:

# chkconfig ypbind off
# service ypbind stop"

  describe.one do
    describe package('ypbind') do
      it { should_not be_installed }
    end
    describe service('ypbind') do
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
