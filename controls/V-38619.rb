control "V-38619" do
  title "There must be no .netrc files on the system."
  desc  "Unencrypted passwords for remote FTP servers may be stored in
\".netrc\" files. DoD policy requires passwords be encrypted in storage and not
used in access scripts."
  impact 0.5
  tag "gtitle": "SRG-OS-000073"
  tag "gid": "V-38619"
  tag "rid": "SV-50420r2_rule"
  tag "stig_id": "RHEL-06-000347"
  tag "fix_id": "F-43569r2_fix"
  tag "cci": ["CCI-000196"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
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
  tag "check": "To check the system for the existence of any \".netrc\" files,
run the following command:

$ sudo find /root /home -xdev -name .netrc

If any .netrc files exist, this is a finding."
  tag "fix": "The \".netrc\" files contain logon information used to auto-logon
into FTP servers and reside in the user's home directory. These files may
contain unencrypted passwords to remote FTP servers making them susceptible to
access by unauthorized users and should not be used. Any \".netrc\" files
should be removed."

  describe command('find /root /home -xdev -name .netrc') do
    its('stdout') { should be_empty }
  end
end

