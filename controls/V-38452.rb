control "V-38452" do
  title "The system package management tool must verify permissions on all
files and directories associated with packages."
  desc  "Permissions on system binaries and configuration files that are too
generous could allow an unauthorized user to gain privileges that they should
not have. The permissions set by the vendor should be maintained. Any
deviations from this baseline should be investigated."
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38452"
  tag "rid": "SV-50252r2_rule"
  tag "stig_id": "RHEL-06-000518"
  tag "fix_id": "F-43398r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "The following command will list which files and directories on
the system have permissions different from what is expected by the RPM
database:

# rpm -Va  | grep '^.M'

If there is any output, for each file or directory found, find the associated
RPM package and compare the RPM-expected permissions with the actual
permissions on the file or directory:

# rpm -qf [file or directory name]
# rpm -q --queryformat \"[%{FILENAMES} %{FILEMODES:perms}\
]\" [package] | grep  [filename]
# ls -dlL [filename]

If the existing permissions are more permissive than those expected by RPM,
this is a finding."
  tag "fix": "The RPM package management system can restore file access
permissions of package files and directories. The following command will update
permissions on files and directories with permissions different from what is
expected by the RPM database:

# rpm --setperms [package]"

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

