control 'V-38581' do
  title "The system boot loader configuration file(s) must be group-owned by
root."
  desc  "The \"root\" group is a highly-privileged group. Furthermore, the
group-owner of this file should not have any access privileges anyway."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38581'
  tag "rid": 'SV-50382r2_rule'
  tag "stig_id": 'RHEL-06-000066'
  tag "fix_id": 'F-43529r2_fix'
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
  tag "check": "To check the group ownership of \"/boot/grub/grub.conf\", run
the command:

$ ls -lL /boot/grub/grub.conf

If properly configured, the output should indicate the group-owner is \"root\".
If it does not, this is a finding."
  tag "fix": "The file \"/boot/grub/grub.conf\" should be group-owned by the
\"root\" group to prevent destruction or modification of the file. To properly
set the group owner of \"/boot/grub/grub.conf\", run the command:

# chgrp root /boot/grub/grub.conf"

  describe.one do
    describe file('/boot/grub/grub.conf') do
      it { should exist }
    end
    describe file('/boot/grub/grub.conf') do
      its('gid') { should cmp 0 }
    end
    describe file('/boot/efi/EFI/redhat/grub.conf') do
      it { should exist }
    end
    describe file('/boot/efi/EFI/redhat/grub.conf') do
      its('gid') { should cmp 0 }
    end
  end
end
