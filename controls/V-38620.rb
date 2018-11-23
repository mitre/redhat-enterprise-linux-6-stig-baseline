control 'V-38620' do
  title 'The system clock must be synchronized continuously, or at least daily.'
  desc  "Enabling the \"ntpd\" service ensures that the \"ntpd\" service will
be running and that the system will synchronize its time to any servers
specified. This is important whether the system is configured to be a client
(and synchronize only its own clock) or it is also acting as an NTP server to
other systems. Synchronizing time is essential for authentication services such
as Kerberos, but it is also important for maintaining accurate logs and
auditing possible security breaches."
  impact 0.5
  tag "gtitle": 'SRG-OS-000056'
  tag "gid": 'V-38620'
  tag "rid": 'SV-50421r1_rule'
  tag "stig_id": 'RHEL-06-000247'
  tag "fix_id": 'F-43568r1_fix'
  tag "cci": ['CCI-000160']
  tag "nist": ['AU-8 (1)', 'Rev_4']
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
  tag "check": "Run the following command to determine the current status of
the \"ntpd\" service:

# service ntpd status

If the service is enabled, it should return the following:

ntpd is running...


If the service is not running, this is a finding."
  tag "fix": "The \"ntpd\" service can be enabled with the following command:

# chkconfig ntpd on
# service ntpd start"

  describe package('ntp') do
    it { should be_installed }
  end
  describe.one do
    describe service('ntpd').runlevels(/0/) do
      it { should be_enabled }
    end
    describe service('ntpd').runlevels(/1/) do
      it { should be_enabled }
    end
    describe service('ntpd').runlevels(/2/) do
      it { should be_enabled }
    end
    describe service('ntpd').runlevels(/3/) do
      it { should be_enabled }
    end
    describe service('ntpd').runlevels(/4/) do
      it { should be_enabled }
    end
    describe service('ntpd').runlevels(/5/) do
      it { should be_enabled }
    end
    describe service('ntpd').runlevels(/6/) do
      it { should be_enabled }
    end
  end
end
