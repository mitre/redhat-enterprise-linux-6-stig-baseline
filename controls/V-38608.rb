control 'V-38608' do
  title 'The SSH daemon must set a timeout interval on idle sessions.'
  desc  "Causing idle users to be automatically logged out guards against
compromises one system leading trivially to compromises on another."
  impact 0.3
  tag "gtitle": 'SRG-OS-000163'
  tag "gid": 'V-38608'
  tag "rid": 'SV-50409r1_rule'
  tag "stig_id": 'RHEL-06-000230'
  tag "fix_id": 'F-43556r1_fix'
  tag "cci": ['CCI-001133']
  tag "nist": ['SC-10', 'Rev_4']
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
  tag "check": "Run the following command to see what the timeout interval is:

# grep ClientAliveInterval /etc/ssh/sshd_config

If properly configured, the output should be:

ClientAliveInterval 900


If it is not, this is a finding."
  tag "fix": "SSH allows administrators to set an idle timeout interval. After
this interval has passed, the idle user will be automatically logged out.

To set an idle timeout interval, edit the following line in
\"/etc/ssh/sshd_config\" as follows:

ClientAliveInterval [interval]

The timeout [interval] is given in seconds. To have a timeout of 15 minutes,
set [interval] to 900.

If a shorter timeout has already been set for the login shell, that value will
preempt any SSH setting made here. Keep in mind that some processes may stop
SSH from correctly detecting that the user is idle."

  describe sshd_config do
    its('ClientAliveInterval') { should_not be_nil }
  end
end
