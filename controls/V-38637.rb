control "V-38637" do
  title "The system package management tool must verify contents of all files
associated with the audit package."
  desc  "The hash on important files like audit system executables should match
the information given by the RPM database. Audit executables  with erroneous
hashes could be a sign of nefarious activity on the system."
  impact 0.5
  tag "gtitle": "SRG-OS-000278"
  tag "gid": "V-38637"
  tag "rid": "SV-50438r2_rule"
  tag "stig_id": "RHEL-06-000281"
  tag "fix_id": "F-43586r1_fix"
  tag "cci": ["CCI-001496"]
  tag "nist": ["AU-9 (3)", "Rev_4"]
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
have file hashes different from what is expected by the RPM database.

# rpm -V audit | awk '$1 ~ /..5/ && $2 != \"c\"'


If there is output, this is a finding."
  tag "fix": "The RPM package management system can check the hashes of audit
system package files. Run the following command to list which audit files on
the system have hashes that differ from what is expected by the RPM database:

# rpm -V audit | grep '^..5'

A \"c\" in the second column indicates that a file is a configuration file,
which may appropriately be expected to change. If the file that has changed was
not expected to then refresh from distribution media or online repositories.

rpm -Uvh [affected_package]

OR

yum reinstall [affected_package]"

  describe command("rpm -V audit | awk '$1 ~ /..5/ && $2 != \"c\"'") do
    its('stdout.strip') { should be_empty }
  end
end

