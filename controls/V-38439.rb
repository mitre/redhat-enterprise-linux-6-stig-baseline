control 'V-38439' do
  title "The system must provide automated support for account management
functions."
  desc  "A comprehensive account management process that includes automation
helps to ensure the accounts designated as requiring attention are consistently
and promptly addressed. Enterprise environments make user account management
challenging and complex. A user management process requiring administrators to
manually address account management functions adds risk of potential oversight."
  impact 0.5
  tag "gtitle": 'SRG-OS-000001'
  tag "gid": 'V-38439'
  tag "rid": 'SV-50239r1_rule'
  tag "stig_id": 'RHEL-06-000524'
  tag "fix_id": 'F-43384r1_fix'
  tag "cci": ['CCI-000015']
  tag "nist": ['AC-2 (1)', 'Rev_4']
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
  tag "check": "Interview the SA to determine if there is an automated system
for managing user accounts, preferably integrated with an existing enterprise
user management system.

If there is not, this is a finding."
  tag "fix": "Implement an automated system for managing user accounts that
minimizes the risk of errors, either intentional or deliberate.  If possible,
this system should integrate with an existing enterprise user management
system, such as, one based Active Directory or Kerberos."

  describe 'Manual test' do
    skip 'This control must be reviewed manually'
  end
end
