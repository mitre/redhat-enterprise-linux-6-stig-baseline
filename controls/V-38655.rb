control 'V-38655' do
  title 'The noexec option must be added to removable media partitions.'
  desc  "Allowing users to execute binaries from removable media such as USB
keys exposes the system to potential compromise."
  impact 0.3
  tag "gtitle": 'SRG-OS-000035'
  tag "gid": 'V-38655'
  tag "rid": 'SV-50456r1_rule'
  tag "stig_id": 'RHEL-06-000271'
  tag "fix_id": 'F-43605r1_fix'
  tag "cci": ['CCI-000087']
  tag "nist": ['AC-19 e', 'Rev_4']
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

  mounts = command('mount').stdout.strip.split("\n")
                           .map do |d|
    split_mounts = d.split(/\s+/)
    options = split_mounts[-1].match(/\((.*)\)$/).captures.first.split(',')
    dev_file = file(split_mounts[0])
    dev_link = dev_file.symlink? ? dev_file.link_path : dev_file.path
    { 'dev' => split_mounts[0], 'link' => dev_link, 'mount' => split_mounts[2], 'options' => options }
  end

  dev_mounts = mounts
               .select { |mnt| mnt['dev'].start_with?('/') && !mnt['dev'].start_with?('//') }
               .map do |mnt|
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
    describe 'Removable mounted devices' do
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
