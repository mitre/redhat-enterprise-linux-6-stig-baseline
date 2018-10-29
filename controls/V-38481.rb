control "V-38481" do
  title "System security patches and updates must be installed and up-to-date."
  desc  "Installing software updates is a fundamental mitigation against the
exploitation of publicly-known vulnerabilities."
  impact 0.5
  tag "gtitle": "SRG-OS-000191"
  tag "gid": "V-38481"
  tag "rid": "SV-50281r1_rule"
  tag "stig_id": "RHEL-06-000011"
  tag "fix_id": "F-43426r1_fix"
  tag "cci": ["CCI-001233"]
  tag "nist": ["SI-2 (2)", "Rev_4"]
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
  tag "check": "If the system is joined to the Red Hat Network, a Red Hat
Satellite Server, or a yum server which provides updates, invoking the
following command will indicate if updates are available:

# yum check-update

If the system is not configured to update from one of these sources, run the
following command to list when each package was last updated:

$ rpm -qa -last

Compare this to Red Hat Security Advisories (RHSA) listed at
https://access.redhat.com/security/updates/active/ to determine whether the
system is missing applicable security and bugfix  updates.
If updates are not installed, this is a finding."
  tag "fix": "If the system is joined to the Red Hat Network, a Red Hat
Satellite Server, or a yum server, run the following command to install
updates:

# yum update

If the system is not configured to use one of these sources, updates (in the
form of RPM packages) can be manually downloaded from the Red Hat Network and
installed using \"rpm\"."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

