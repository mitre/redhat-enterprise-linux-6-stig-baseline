control 'V-38583' do
  title "The system boot loader configuration file(s) must have mode 0600 or
less permissive."
  desc  "Proper permissions ensure that only the root user can modify important
boot parameters."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38583'
  tag "rid": 'SV-50384r4_rule'
  tag "stig_id": 'RHEL-06-000067'
  tag "fix_id": 'F-43531r3_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "To check the permissions of \"/boot/grub/grub.conf\", run the
command:

$ sudo ls -lL /boot/grub/grub.conf

If the system uses UEFI check the permissions of
\"/boot/efi/EFI/redhat/grub.conf\" file:

$ sudo ls –lL /boot/efi/EFI/redhat/grub.conf

If properly configured, the output should indicate the following permissions:
\"-rw-------\"

If it does not, this is a finding."
  tag "fix": "File permissions for \"/boot/grub/grub.conf\" and
\"/boot/efi/EFI/redhat/grub.conf\" should be set to 600, which is the default.

To properly set the permissions of \"/boot/grub/grub.conf\", run the command:

$ chmod 600 /boot/grub/grub.conf

To properly set the permissions of \"/boot/efi/EFI/redhat/grub.conf\", run the
command:

$ chmod 600 /boot/efi/EFI/redhat/grub.conf

Boot partitions based on VFAT, NTFS, or other non-standard configurations may
require alternative measures.
"

  describe file('/boot/grub/grub.conf') do
    it { should exist }
  end
  describe file('/boot/grub/grub.conf') do
    it { should_not be_executable.by 'group' }
  end
  describe file('/boot/grub/grub.conf') do
    it { should_not be_readable.by 'group' }
  end
  describe file('/boot/grub/grub.conf') do
    it { should_not be_writable.by 'group' }
  end
  describe file('/boot/grub/grub.conf') do
    it { should_not be_executable.by 'other' }
  end
  describe file('/boot/grub/grub.conf') do
    it { should_not be_readable.by 'other' }
  end
  describe file('/boot/grub/grub.conf') do
    it { should_not be_writable.by 'other' }
  end
  describe file('/boot/grub/grub.conf') do
    it { should_not be_executable.by 'owner' }
  end
  describe file('/boot/grub/grub.conf') do
    it { should be_readable.by 'owner' }
  end
  describe file('/boot/grub/grub.conf') do
    it { should be_writable.by 'owner' }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should exist }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should_not be_executable.by 'group' }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should_not be_readable.by 'group' }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should_not be_writable.by 'group' }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should_not be_executable.by 'other' }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should_not be_readable.by 'other' }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should_not be_writable.by 'other' }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should_not be_executable.by 'owner' }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should be_readable.by 'owner' }
  end
  describe file('/boot/efi/EFI/redhat/grub.conf') do
    it { should be_writable.by 'owner' }
  end
end
