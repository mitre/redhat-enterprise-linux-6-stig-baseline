control "V-38654" do
  title "Remote file systems must be mounted with the nosuid option."
  desc  "NFS mounts should not present suid binaries to users. Only
vendor-supplied suid executables should be installed to their default location
on the local filesystem."
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38654"
  tag "rid": "SV-50455r2_rule"
  tag "stig_id": "RHEL-06-000270"
  tag "fix_id": "F-43603r1_fix"
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
  desc 'check', "To verify the \"nosuid\" option is configured for all NFS
mounts, run the following command:

$ mount | grep nfs

All NFS mounts should show the \"nosuid\" setting in parentheses, along with
other mount options.
If the setting does not show, this is a finding."
  desc 'fix', "Add the \"nosuid\" option to the fourth column of \"/etc/fstab\"
for the line which controls mounting of any NFS mounts."

  describe command('mount | grep nfs') do
    its('stdout.strip.lines') { should all include 'nosuid' }
  end
end

