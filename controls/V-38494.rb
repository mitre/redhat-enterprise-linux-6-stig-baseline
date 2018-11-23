control "V-38494" do
  title "The system must prevent the root account from logging in from serial
consoles."
  desc  "Preventing direct root login to serial port interfaces helps ensure
accountability for actions taken on the systems using the root account."
  impact 'low'
  tag "gtitle": "SRG-OS-000109"
  tag "gid": "V-38494"
  tag "rid": "SV-50295r1_rule"
  tag "stig_id": "RHEL-06-000028"
  tag "fix_id": "F-43441r1_fix"
  tag "cci": ["CCI-000770"]
  tag "nist": ["IA-2 (5)", "Rev_4"]
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
  desc 'check', "To check for serial port entries which permit root login, run
the following command:

# grep '^ttyS[0-9]' /etc/securetty

If any output is returned, then root login over serial ports is permitted.
If root login over serial ports is permitted, this is a finding."
  desc 'fix', "To restrict root logins on serial ports, ensure lines of this
form do not appear in \"/etc/securetty\":

ttyS0
ttyS1

Note:  Serial port entries are not limited to those listed above.  Any lines
starting with \"ttyS\" followed by numerals should be removed"

  describe file("/etc/securetty") do
    its("content") { should_not match(/^ttyS[0-9]+$/) }
  end
end

