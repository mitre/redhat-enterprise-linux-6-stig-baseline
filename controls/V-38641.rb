control "V-38641" do
  title "The atd service must be disabled."
  desc  "The \"atd\" service could be used by an unsophisticated insider to
carry out activities outside of a normal login session, which could complicate
accountability. Furthermore, the need to schedule tasks with \"at\" or
\"batch\" is not common."
  impact 'low'
  tag "gtitle": "SRG-OS-000096"
  tag "gid": "V-38641"
  tag "rid": "SV-50442r3_rule"
  tag "stig_id": "RHEL-06-000262"
  tag "fix_id": "F-43590r2_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
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
  desc 'check', "If the system requires the use of the \"atd\" service to
support an organizational requirement, this is not applicable.

To check that the \"atd\" service is disabled in system boot configuration, run
the following command:

# chkconfig \"atd\" --list

Output should indicate the \"atd\" service has either not been installed, or
has been disabled at all runlevels, as shown in the example below:

# chkconfig \"atd\" --list
\"atd\" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"atd\" is disabled through current runtime
configuration:

# service atd status

If the service is disabled the command will return the following output:

atd is stopped


If the service is running, this is a finding."
  desc 'fix', "The \"at\" and \"batch\" commands can be used to schedule tasks
that are meant to be executed only once. This allows delayed execution in a
manner similar to cron, except that it is not recurring. The daemon \"atd\"
keeps track of tasks scheduled via \"at\" and \"batch\", and executes them at
the specified time. The \"atd\" service can be disabled with the following
commands:

# chkconfig atd off
# service atd stop"

  describe.one do
    describe package("at") do
      it { should_not be_installed }
    end
    describe service("atd") do
      its("runlevels(?-mix:0)") { should be_enabled }
      its("runlevels(?-mix:1)") { should be_enabled }
      its("runlevels(?-mix:2)") { should be_enabled }
      its("runlevels(?-mix:3)") { should be_enabled }
      its("runlevels(?-mix:4)") { should be_enabled }
      its("runlevels(?-mix:5)") { should be_enabled }
      its("runlevels(?-mix:6)") { should be_enabled }
    end
  end
end

