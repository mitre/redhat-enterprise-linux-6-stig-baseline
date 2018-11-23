control 'V-38660' do
  title 'The snmpd service must use only SNMP protocol version 3 or newer.'
  desc  "Earlier versions of SNMP are considered insecure, as they potentially
allow unauthorized access to detailed system management information.

  "
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38660'
  tag "rid": 'SV-50461r1_rule'
  tag "stig_id": 'RHEL-06-000340'
  tag "fix_id": 'F-43604r1_fix'
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
  tag "check": "To ensure only SNMPv3 or newer is used, run the following
command:

# grep 'v1\\|v2c\\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#'

There should be no output.
If there is output, this is a finding."
  tag "fix": "Edit \"/etc/snmp/snmpd.conf\", removing any references to \"v1\",
\"v2c\", or \"com2sec\". Upon doing that, restart the SNMP service:

# service snmpd restart"

  describe command("grep 'v1\\|v2c\\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#'") do
    its('stdout.strip') { should be_empty }
  end
end
