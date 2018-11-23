control 'V-38470' do
  title "The audit system must alert designated staff members when the audit
storage volume approaches capacity."
  desc  "Notifying administrators of an impending disk space problem may allow
them to take corrective action prior to any disruption."
  impact 0.5
  tag "gtitle": 'SRG-OS-000045'
  tag "gid": 'V-38470'
  tag "rid": 'SV-50270r2_rule'
  tag "stig_id": 'RHEL-06-000005'
  tag "fix_id": 'F-43415r2_fix'
  tag "cci": ['CCI-000138']
  tag "nist": ['AU-4', 'Rev_4']
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
  tag "check": "Inspect \"/etc/audit/auditd.conf\" and locate the following
line to determine if the system is configured to email the administrator when
disk space is starting to run low:

# grep space_left_action /etc/audit/auditd.conf
space_left_action = email


If the system is not configured to send an email to the system administrator
when disk space is starting to run low, this is a finding.  The \"syslog\"
option is acceptable when it can be demonstrated that the local log management
infrastructure notifies an appropriate administrator in a timely manner."
  tag "fix": "The \"auditd\" service can be configured to take an action when
disk space starts to run low. Edit the file \"/etc/audit/auditd.conf\". Modify
the following line, substituting [ACTION] appropriately:

space_left_action = [ACTION]

Possible values for [ACTION] are described in the \"auditd.conf\" man page.
These include:

\"ignore\"
\"syslog\"
\"email\"
\"exec\"
\"suspend\"
\"single\"
\"halt\"


Set this to \"email\" (instead of the default, which is \"suspend\") as it is
more likely to get prompt attention.  The \"syslog\" option is acceptable,
provided the local log management infrastructure notifies an appropriate
administrator in a timely manner.

RHEL-06-000521 ensures that the email generated through the operation
\"space_left_action\" will be sent to an administrator."

  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^[ ]*space_left_action[ ]+=[ ]+(\S+)[ ]*$/) }
  end
  file('/etc/audit/auditd.conf').content.to_s.scan(/^[ ]*space_left_action[ ]+=[ ]+(\S+)[ ]*$/).flatten.each do |entry|
    describe entry do
      it { should cmp 'email' }
    end
  end
end
