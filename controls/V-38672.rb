control 'V-38672' do
  title 'The netconsole service must be disabled unless required.'
  desc  "The \"netconsole\" service is not necessary unless there is a need to
debug kernel panics, which is not common."
  impact 0.3
  tag "gtitle": 'SRG-OS-000096'
  tag "gid": 'V-38672'
  tag "rid": 'SV-50473r2_rule'
  tag "stig_id": 'RHEL-06-000289'
  tag "fix_id": 'F-43622r2_fix'
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
  tag "check": "To check that the \"netconsole\" service is disabled in system
boot configuration, run the following command:

# chkconfig \"netconsole\" --list

Output should indicate the \"netconsole\" service has either not been
installed, or has been disabled at all runlevels, as shown in the example
below:

# chkconfig \"netconsole\" --list
\"netconsole\" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"netconsole\" is disabled through current
runtime configuration:

# service netconsole status

If the service is disabled the command will return the following output:

netconsole is stopped


If the service is running, this is a finding."
  tag "fix": "The \"netconsole\" service is responsible for loading the
netconsole kernel module, which logs kernel printk messages over UDP to a
syslog server. This allows debugging of problems where disk logging fails and
serial consoles are impractical. The \"netconsole\" service can be disabled
with the following commands:

# chkconfig netconsole off
# service netconsole stop"

  describe service('netconsole').runlevels(/0/) do
    it { should_not be_enabled }
  end
  describe service('netconsole').runlevels(/1/) do
    it { should_not be_enabled }
  end
  describe service('netconsole').runlevels(/2/) do
    it { should_not be_enabled }
  end
  describe service('netconsole').runlevels(/3/) do
    it { should_not be_enabled }
  end
  describe service('netconsole').runlevels(/4/) do
    it { should_not be_enabled }
  end
  describe service('netconsole').runlevels(/5/) do
    it { should_not be_enabled }
  end
  describe service('netconsole').runlevels(/6/) do
    it { should_not be_enabled }
  end
end
