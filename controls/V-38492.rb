control 'V-38492' do
  title "The system must prevent the root account from logging in from virtual
consoles."
  desc  "Preventing direct root login to virtual console devices helps ensure
accountability for actions taken on the system using the root account. "
  impact 0.5
  tag "gtitle": 'SRG-OS-000109'
  tag "gid": 'V-38492'
  tag "rid": 'SV-50293r1_rule'
  tag "stig_id": 'RHEL-06-000027'
  tag "fix_id": 'F-43439r2_fix'
  tag "cci": ['CCI-000770']
  tag "nist": ['IA-2 (5)', 'Rev_4']
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
  tag "check": "To check for virtual console entries which permit root login,
run the following command:

# grep '^vc/[0-9]' /etc/securetty

If any output is returned, then root logins over virtual console devices is
permitted.
If root login over virtual console devices is permitted, this is a finding."
  tag "fix": "To restrict root logins through the (deprecated) virtual console
devices, ensure lines of this form do not appear in \"/etc/securetty\":

vc/1
vc/2
vc/3
vc/4

Note:  Virtual console entries are not limited to those listed above.  Any
lines starting with \"vc/\" followed by numerals should be removed."

  describe file('/etc/securetty') do
    its('content') { should_not match(/^vc\/[0-9]+$/) }
  end
end
