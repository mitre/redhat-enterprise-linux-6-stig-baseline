control "V-38652" do
  title "Remote file systems must be mounted with the nodev option."
  desc  "Legitimate device files should only exist in the /dev directory. NFS
mounts should not present device files to users."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38652"
  tag "rid": "SV-50453r2_rule"
  tag "stig_id": "RHEL-06-000269"
  tag "fix_id": "F-43601r1_fix"
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
  tag "check": "To verify the \"nodev\" option is configured for all NFS
mounts, run the following command:

$ mount | grep \"nfs \"

All NFS mounts should show the \"nodev\" setting in parentheses, along with
other mount options.
If the setting does not show, this is a finding."
  tag "fix": "Add the \"nodev\" option to the fourth column of \"/etc/fstab\"
for the line which controls mounting of any NFS mounts."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

