# encoding: UTF-8

control "SV-218025" do
  title "The system must use SMB client signing for connecting to samba servers using mount.cifs."
  desc "Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit."
  desc "default", "Packet signing can prevent man-in-the-middle attacks which modify SMB
packets in transit."
  desc "check", "If Samba is not in use, this is not applicable.

To verify that Samba clients using mount.cifs must use packet signing, run the following command: 

# grep sec /etc/fstab /etc/mtab

The output should show either \"krb5i\" or \"ntlmv2i\" in use. 
If it does not, this is a finding."
  desc "fix", "Require packet signing of clients who mount Samba shares using the \"mount.cifs\" program (e.g., those who specify shares in \"/etc/fstab\"). To do so, ensure signing options (either \"sec=krb5i\" or \"sec=ntlmv2i\") are used. 

See the \"mount.cifs(8)\" man page for more information. A Samba client should only communicate with servers who can support SMB packet signing."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218025"
  tag rid: "SV-218025r603264_rule"
  tag stig_id: "RHEL-06-000273"
  tag fix_id: "F-19504r377091_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  mounts = command('mount').stdout.strip.split("\n").
    map do |d|
      split_mounts = d.split(%r{\s+})
      options = split_mounts[-1].match(%r{\((.*)\)$}).captures.first.split(',')
      dev_file = file(split_mounts[0])
      dev_link = dev_file.symlink? ? dev_file.link_path : dev_file.path
      {'dev'=>split_mounts[0], 'link'=>dev_link, 'mount'=>split_mounts[2], 'options'=>options, 'type'=> split_mounts[-2]}
    end
  cifs_mounts = mounts.select { |mnt| mnt['type'] == 'cifs' }
  if cifs_mounts.empty?
    impact 0.0
    describe "Samba shares not in use" do
      skip "Samba shares not in use, this control Not Applicable"
    end
  else
    cifs_mounts.each do |mnt|
      describe "Mount #{mnt['mount']} options" do
        subject { mnt['options'] }
        it { should (include 'sec=krb5i').or include 'sec=ntlmv2i' }
      end
    end
  end
end