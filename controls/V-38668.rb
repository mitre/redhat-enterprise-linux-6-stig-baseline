control 'V-38668' do
  title 'The x86 Ctrl-Alt-Delete key sequence must be disabled.'
  desc  "A locally logged-in user who presses Ctrl-Alt-Delete, when at the
console, can reboot the system. If accidentally pressed, as could happen in the
case of mixed OS environment, this can create the risk of short-term loss of
availability of systems due to unintentional reboot. In the GNOME graphical
environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
reduced because the user will be prompted before any action is taken."
  impact 0.7
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38668'
  tag "rid": 'SV-50469r4_rule'
  tag "stig_id": 'RHEL-06-000286'
  tag "fix_id": 'F-43617r3_fix'
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
  tag "check": "To ensure the system is configured to log a message instead of
rebooting the system when Ctrl-Alt-Delete is pressed, ensure the following line
is in \"/etc/init/control-alt-delete.override\":

exec /usr/bin/logger -p authpriv.notice \"Ctrl-Alt-Delete pressed\"

If the system is not configured to block the shutdown command when
Ctrl-Alt-Delete is pressed, this is a finding. "
  tag "fix": "By default, the system includes the following line in
\"/etc/init/control-alt-delete.conf\" to reboot the system when the
Ctrl-Alt-Delete key sequence is pressed:

exec /sbin/shutdown -r now \"Ctrl-Alt-Delete pressed\"


To configure the system to log a message instead of rebooting the system, add
the following line to \"/etc/init/control-alt-delete.override\" to read as
follows:

exec /usr/bin/logger -p authpriv.notice \"Ctrl-Alt-Delete pressed\""

  describe file('/etc/init/control-alt-delete.override') do
    its('content') { should match(/^\s*exec \/usr\/bin\/logger -p authpriv\.notice "Ctrl-Alt-Delete pressed"\s*$/) }
  end
end
