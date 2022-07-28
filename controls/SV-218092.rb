# encoding: UTF-8

control "SV-218092" do
  title "The system must forward audit records to the syslog service."
  desc "The auditd service does not include the ability to send audit records to a centralized server for management directly.  It does, however, include an audit event multiplexor plugin (audispd) to pass audit records to the local syslog server."
  desc "default", "The auditd service does not include the ability to send audit records
to a centralized server for management directly.  It does, however, include an
audit event multiplexor plugin (audispd) to pass audit records to the local
syslog server."
  desc "check", "Verify the audispd plugin is active:

# grep active /etc/audisp/plugins.d/syslog.conf

If the \"active\" setting is missing or set to \"no\", this is a finding."
  desc "fix", "Set the \"active\" line in \"/etc/audisp/plugins.d/syslog.conf\" to \"yes\".  Restart the auditd process.

# service auditd restart"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000342"
  tag gid: "V-218092"
  tag rid: "SV-218092r603264_rule"
  tag stig_id: "RHEL-06-000509"
  tag fix_id: "F-19571r377292_fix"
  tag cci: ["CCI-000136", "CCI-001851"]
  tag nist: ["AU-3 (2)", "Rev_4", "AU-4 (1)"]

  describe parse_config_file('/etc/audisp/plugins.d/syslog.conf') do
    its('active') { should eq 'yes' }
  end
end