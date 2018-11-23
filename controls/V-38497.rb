control 'V-38497' do
  title "The system must not have accounts configured with blank or null
passwords."
  desc  "If an account has an empty password, anyone could log in and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments."
  impact 0.7
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38497'
  tag "rid": 'SV-50298r3_rule'
  tag "stig_id": 'RHEL-06-000030'
  tag "fix_id": 'F-43444r5_fix'
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
  tag "check": "To verify that null passwords cannot be used, run the following
command:

# grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth

If this produces any output, it may be possible to log into accounts with empty
passwords.
If NULL passwords can be used, this is a finding."
  tag "fix": "If an account is configured for password authentication but does
not have an assigned password, it may be possible to log onto the account
without authentication. Remove any instances of the \"nullok\" option in
\"/etc/pam.d/system-auth\" and \"/etc/pam.d/password-auth\" to prevent logons
with empty passwords."

  describe file('/etc/pam.d/system-auth') do
    its('content') { should_not match(/^[^#]\s*.*\snullok\s*/) }
  end
  describe file('/etc/pam.d/password-auth') do
    its('content') { should_not match(/^[^#]\s*.*\snullok\s*/) }
  end
end
