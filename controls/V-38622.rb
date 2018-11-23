control 'V-38622' do
  title 'Mail relaying must be restricted.'
  desc  "This ensures \"postfix\" accepts mail messages (such as cron job
reports) from the local system only, and not from the network, which protects
it from network attack."
  impact 0.5
  tag "gtitle": 'SRG-OS-000096'
  tag "gid": 'V-38622'
  tag "rid": 'SV-50423r2_rule'
  tag "stig_id": 'RHEL-06-000249'
  tag "fix_id": 'F-43572r1_fix'
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
  tag "check": "If the system is an authorized mail relay host, this is not
applicable.

Run the following command to ensure postfix accepts mail messages from only the
local system:

$ grep inet_interfaces /etc/postfix/main.cf

If properly configured, the output should show only \"localhost\".
If it does not, this is a finding."
  tag "fix": "Edit the file \"/etc/postfix/main.cf\" to ensure that only the
following \"inet_interfaces\" line appears:

inet_interfaces = localhost"

  describe file('/etc/postfix/main.cf') do
    its('content') { should match(/^[\s]*inet_interfaces[\s]*=[\s]*localhost[\s]*$/) }
  end
end
