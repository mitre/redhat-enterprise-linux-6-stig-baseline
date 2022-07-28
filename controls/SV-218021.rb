# encoding: UTF-8

control "SV-218021" do
  title "Remote file systems must be mounted with the nodev option."
  desc "Legitimate device files should only exist in the /dev directory. NFS mounts should not present device files to users."
  desc "default", "Legitimate device files should only exist in the /dev directory. NFS
mounts should not present device files to users."
  desc "check", "To verify the \"nodev\" option is configured for all NFS mounts, run the following command: 

$ mount | grep \"nfs \"

All NFS mounts should show the \"nodev\" setting in parentheses, along with other mount options. 
If the setting does not show, this is a finding."
  desc "fix", "Add the \"nodev\" option to the fourth column of \"/etc/fstab\" for the line which controls mounting of any NFS mounts."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218021"
  tag rid: "SV-218021r603264_rule"
  tag stig_id: "RHEL-06-000269"
  tag fix_id: "F-19500r377079_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe command('mount | grep \"nfs \"') do
    its('stdout.strip.lines') { should all include 'nodev' }
  end
end