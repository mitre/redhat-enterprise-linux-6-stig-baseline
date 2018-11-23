control 'V-38663' do
  title "The system package management tool must verify permissions on all
files and directories associated with the audit package."
  desc  "Permissions on audit binaries and configuration files that are too
generous could allow an unauthorized user to gain privileges that they should
not have. The permissions set by the vendor should be maintained. Any
deviations from this baseline should be investigated."
  impact 0.5
  tag "gtitle": 'SRG-OS-000256'
  tag "gid": 'V-38663'
  tag "rid": 'SV-50464r1_rule'
  tag "stig_id": 'RHEL-06-000278'
  tag "fix_id": 'F-43612r1_fix'
  tag "cci": ['CCI-001493']
  tag "nist": ['AU-9', 'Rev_4']
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
  tag "check": "The following command will list which audit files on the system
have permissions different from what is expected by the RPM database:

# rpm -V audit | grep '^.M'

If there is any output, for each file or directory found, compare the
RPM-expected permissions with the permissions on the file or directory:

# rpm -q --queryformat \"[%{FILENAMES} %{FILEMODES:perms}\
]\" audit | grep  [filename]
# ls -lL [filename]

If the existing permissions are more permissive than those expected by RPM,
this is a finding."
  tag "fix": "The RPM package management system can restore file access
permissions of the audit package files and directories. The following command
will update audit files with permissions different from what is expected by the
RPM database:

# rpm --setperms audit"

  describe command('rpm -V audit | grep \'^.M\'') do
    its('stdout.strip') { should be_empty }
  end
end
