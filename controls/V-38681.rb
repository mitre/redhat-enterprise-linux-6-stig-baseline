control "V-38681" do
  title "All GIDs referenced in /etc/passwd must be defined in /etc/group"
  desc  "Inconsistency in GIDs between /etc/passwd and /etc/group could lead to
a user having unintended rights."
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38681"
  tag "rid": "SV-50482r2_rule"
  tag "stig_id": "RHEL-06-000294"
  tag "fix_id": "F-43630r1_fix"
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
  tag "check": "To ensure all GIDs referenced in /etc/passwd are defined in
/etc/group, run the following command:

# pwck -r | grep 'no group'

There should be no output.
If there is output, this is a finding."
  tag "fix": "Add a group to the system for each GID referenced without a
corresponding group."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

