# encoding: UTF-8

control "SV-218023" do
  title "The noexec option must be added to removable media partitions."
  desc "Allowing users to execute binaries from removable media such as USB keys exposes the system to potential compromise."
  desc "default", "Allowing users to execute binaries from removable media such as USB
keys exposes the system to potential compromise."
  desc "check", "Identify any removable media that is configured on the system:

# cat /etc/fstab

/dev/mapper/vg_rhel6-lv_root /                       ext4    defaults        1 1
UUID=0be9b205-f8e6-4bf4-b0ba-1f235fc55936 /boot      ext4    defaults        1 2
UUID=5D49-30B2          /boot/efi               vfat    umask=0077,shortname=winnt 0 0
/dev/mapper/vg_rhel6-lv_home /home              ext4    defaults        1 2
/dev/mapper/vg_rhel6-lv_tmp /tmp                    ext4    defaults        1 2
/dev/mapper/vg_rhel6-lv_var /var                       ext4    defaults        1 2
/dev/mapper/vg_rhel6-lv_swap swap                 swap   defaults        0 0
tmpfs                 /dev/shm          tmpfs     defaults        0 0
devpts               /dev/pts            devpts    gid=5,mode=620  0 0
sysfs                   /sys                    sysfs       defaults        0 0
proc                    /proc                 proc       defaults        0 0
/dev/sdc1         /media/usb       vfat        defaults,rw,noexec 0 0

If any of the identified removable media devices do not have \"noexec\" defined, this is a finding."
  desc "fix", "The \"noexec\" mount option prevents the direct execution of binaries on the mounted filesystem. Users should not be allowed to execute binaries that exist on partitions mounted from removable media (such as a USB key). The \"noexec\" option prevents code from being executed directly from the media itself, and may therefore provide a line of defense against certain types of worms or malicious code. Add the \"noexec\" option to the fourth column of \"/etc/fstab\" for the line which controls mounting of any removable media partitions."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218023"
  tag rid: "SV-218023r603264_rule"
  tag stig_id: "RHEL-06-000271"
  tag fix_id: "F-19502r377085_fix"
  tag cci: ["CCI-000087", "CCI-000366"]
  tag nist: ["AC-19 e", "Rev_4", "CM-6 b"]

  mounts = command('mount').stdout.strip.split("\n").
    map do |d|
      split_mounts = d.split(%r{\s+})
      options = split_mounts[-1].match(%r{\((.*)\)$}).captures.first.split(',')
      dev_file = file(split_mounts[0])
      dev_link = dev_file.symlink? ? dev_file.link_path : dev_file.path
      {'dev'=>split_mounts[0], 'link'=>dev_link, 'mount'=>split_mounts[2], 'options'=>options}
    end
  dev_mounts = mounts.
    select { |mnt| mnt['dev'].start_with? '/' and !mnt['dev'].start_with? '//' }.
    map do |mnt|
      # https://unix.stackexchange.com/a/308724
      partition = ['/sys/class/block', mnt['link'].sub(%r{^/dev/}, ''), 'partition'].join('/')
      if file(partition).exist?
        root_dev = command('basename "$(readlink -f "/sys/class/block/sda1/..")"').stdout.strip
        mnt['root_dev'] = '/dev/' + root_dev
      else
        mnt['root_dev'] = mnt['link']
      end
      mnt
    end
  removable_mounts = dev_mounts.select do |mnt|    
    removable = ['/sys/block', mnt['root_dev'].sub(%r{^/dev/}, ''), 'removable'].join('/')
    file(removable).content.strip == '1'
  end
  if removable_mounts.empty?
    describe "Removable mounted devices" do
      subject { removable_mounts }
      it { should be_empty }
    end
  else
    removable_mounts.each do |mnt|
      describe "Mount #{mnt['mount']} options" do
        subject { mnt['options'] }
        it { should include 'noexec' }
      end
    end
  end
end