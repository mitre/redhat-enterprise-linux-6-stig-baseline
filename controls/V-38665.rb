control "V-38665" do
  title "The system package management tool must verify group-ownership on all
files and directories associated with the audit package."
  desc  "Group-ownership of audit binaries and configuration files that is
incorrect could allow an unauthorized user to gain privileges that they should
not have. The group-ownership set by the vendor should be maintained. Any
deviations from this baseline should be investigated."
  impact 0.5
  tag "gtitle": "SRG-OS-000258"
  tag "gid": "V-38665"
  tag "rid": "SV-50466r1_rule"
  tag "stig_id": "RHEL-06-000280"
  tag "fix_id": "F-43614r1_fix"
  tag "cci": ["CCI-001495"]
  tag "nist": ["AU-9", "Rev_4"]
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
have group-ownership different from what is expected by the RPM database:

# rpm -V audit | grep '^......G'


If there is output, this is a finding."
  tag "fix": "The RPM package management system can restore file
group-ownership of the audit package files and directories. The following
command will update audit files with group-ownership different from what is
expected by the RPM database:

# rpm --setugids audit"

  describe command("rpm -V audit | grep '^......G'") do
    its('stdout.strip') { should be_empty }  
  end
end

