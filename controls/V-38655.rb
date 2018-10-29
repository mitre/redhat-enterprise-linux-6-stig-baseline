control "V-38655" do
  title "The noexec option must be added to removable media partitions."
  desc  "Allowing users to execute binaries from removable media such as USB
keys exposes the system to potential compromise."
  impact 0.3
  tag "gtitle": "SRG-OS-000035"
  tag "gid": "V-38655"
  tag "rid": "SV-50456r1_rule"
  tag "stig_id": "RHEL-06-000271"
  tag "fix_id": "F-43605r1_fix"
  tag "cci": ["CCI-000087"]
  tag "nist": ["AC-19 e", "Rev_4"]
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
  tag "check": "To verify that binaries cannot be directly executed from
removable media, run the following command:

# grep noexec /etc/fstab

The output should show \"noexec\" in use.
If it does not, this is a finding."
  tag "fix": "The \"noexec\" mount option prevents the direct execution of
binaries on the mounted filesystem. Users should not be allowed to execute
binaries that exist on partitions mounted from removable media (such as a USB
key). The \"noexec\" option prevents code from being executed directly from the
media itself, and may therefore provide a line of defense against certain types
of worms or malicious code. Add the \"noexec\" option to the fourth column of
\"/etc/fstab\" for the line which controls mounting of any removable media
partitions."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

