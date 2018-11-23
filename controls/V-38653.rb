control 'V-38653' do
  title 'The snmpd service must not use a default password.'
  desc  "Presence of the default SNMP password enables querying of different
system aspects and could result in unauthorized knowledge of the system."
  impact 0.7
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38653'
  tag "rid": 'SV-50454r1_rule'
  tag "stig_id": 'RHEL-06-000341'
  tag "fix_id": 'F-43602r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "To ensure the default password is not set, run the following
command:

# grep -v \"^#\" /etc/snmp/snmpd.conf| grep public

There should be no output.
If there is output, this is a finding."
  tag "fix": "Edit \"/etc/snmp/snmpd.conf\", remove default community string
\"public\". Upon doing that, restart the SNMP service:

# service snmpd restart"

  describe command('grep -v "^#" /etc/snmp/snmpd.conf| grep public') do
    its('stdout.strip') { should be_empty }
  end
end
