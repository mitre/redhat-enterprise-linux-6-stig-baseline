control "V-38453" do
  title "The system package management tool must verify group-ownership on all
files and directories associated with packages."
  desc  "Group-ownership of system binaries and configuration files that is
incorrect could allow an unauthorized user to gain privileges that they should
not have. The group-ownership set by the vendor should be maintained. Any
deviations from this baseline should be investigated."
  impact 'low'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38453"
  tag "rid": "SV-50253r2_rule"
  tag "stig_id": "RHEL-06-000517"
  tag "fix_id": "F-43399r1_fix"
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
  desc 'check', "The following command will list which files on the system have
group-ownership different from what is expected by the RPM database:

# rpm -Va | grep '^......G'


If any output is produced, verify that the changes were due to STIG application
and have been documented with the ISSO.

If any output has not been documented with the ISSO, this is a finding.
"
  desc 'fix', "The RPM package management system can restore group-ownership of
the package files and directories. The following command will update files and
directories with group-ownership different from what is expected by the RPM
database:

# rpm -qf [file or directory name]
# rpm --setugids [package]"

  # TODO check against an exception list attribute
  describe command("rpm -Va | grep '^......G'") do
    its('stdout.strip') { should eq '' }
  end
end

