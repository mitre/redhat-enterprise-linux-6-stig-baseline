control 'V-38646' do
  title 'The oddjobd service must not be running.'
  desc  "The \"oddjobd\" service may provide necessary functionality in some
environments but it can be disabled if it is not needed. Execution of tasks by
privileged programs, on behalf of unprivileged ones, has traditionally been a
source of privilege escalation security issues."
  impact 0.3
  tag "gtitle": 'SRG-OS-000096'
  tag "gid": 'V-38646'
  tag "rid": 'SV-50447r2_rule'
  tag "stig_id": 'RHEL-06-000266'
  tag "fix_id": 'F-43595r2_fix'
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
  tag "check": "To check that the \"oddjobd\" service is disabled in system
boot configuration, run the following command:

# chkconfig \"oddjobd\" --list

Output should indicate the \"oddjobd\" service has either not been installed,
or has been disabled at all runlevels, as shown in the example below:

# chkconfig \"oddjobd\" --list
\"oddjobd\" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"oddjobd\" is disabled through current
runtime configuration:

# service oddjobd status

If the service is disabled the command will return the following output:

oddjobd is stopped


If the service is running, this is a finding."
  tag "fix": "The \"oddjobd\" service exists to provide an interface and access
control mechanism through which specified privileged tasks can run tasks for
unprivileged client applications. Communication with \"oddjobd\" is through the
system message bus. The \"oddjobd\" service can be disabled with the following
commands:

# chkconfig oddjobd off
# service oddjobd stop"

  describe.one do
    describe package('oddjob') do
      it { should_not be_installed }
    end
    describe service('oddjobd') do
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
