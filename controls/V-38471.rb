control "V-38471" do
  title "The system must forward audit records to the syslog service."
  desc  "The auditd service does not include the ability to send audit records
to a centralized server for management directly.  It does, however, include an
audit event multiplexor plugin (audispd) to pass audit records to the local
syslog server."
  impact 0.3
  tag "gtitle": "SRG-OS-000043"
  tag "gid": "V-38471"
  tag "rid": "SV-50271r1_rule"
  tag "stig_id": "RHEL-06-000509"
  tag "fix_id": "F-43416r1_fix"
  tag "cci": ["CCI-000136"]
  tag "nist": ["AU-3 (2)", "Rev_4"]
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
  tag "check": "Verify the audispd plugin is active:

# grep active /etc/audisp/plugins.d/syslog.conf

If the \"active\" setting is missing or set to \"no\", this is a finding."
  tag "fix": "Set the \"active\" line in \"/etc/audisp/plugins.d/syslog.conf\"
to \"yes\".  Restart the auditd process.

# service auditd restart"

  describe parse_config_file('/etc/audisp/plugins.d/syslog.conf') do
    its('active') { should eq 'yes' }
  end
end

