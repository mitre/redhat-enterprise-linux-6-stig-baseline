control 'V-38585' do
  title 'The system boot loader must require authentication.'
  desc  "Password protection on the boot loader configuration ensures users
with physical access cannot trivially alter important bootloader settings.
These include which kernel to use, and whether to enter single-user mode."
  impact 0.5
  tag "gtitle": 'SRG-OS-000080'
  tag "gid": 'V-38585'
  tag "rid": 'SV-50386r4_rule'
  tag "stig_id": 'RHEL-06-000068'
  tag "fix_id": 'F-43533r3_fix'
  tag "cci": ['CCI-000213']
  tag "nist": ['AC-3', 'Rev_4']
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
  tag "check": "To verify the boot loader password has been set and encrypted,
run the following command:

# grep password /boot/grub/grub.conf

The output should show the following:

password --encrypted $6$[rest-of-the-password-hash]

If it does not, this is a finding.

If the system uses UEFI verify the boot loader password has been set and
encrypted:

# grep password /boot/efi/EFI/redhat/grub.conf"
  tag "fix": "The grub boot loader should have password protection enabled to
protect boot-time settings. To do so, select a password and then generate a
hash from it by running the following command:

# grub-crypt --sha-512

When prompted to enter a password, insert the following line into
\"/boot/grub/grub.conf\" or \"/boot/efi/EFI/redhat/grub.conf\" immediately after
the header comments. (Use the output from \"grub-crypt\" as the value of
[password-hash]):

password --encrypted [password-hash]"

  describe.one do
    describe file('/boot/grub/grub.conf') do
      its('content') { should match(/^\s*password\s+--encrypted\s+.*/) }
    end
    describe file('/boot/efi/EFI/redhat/grub.conf') do
      its('content') { should match(/^\s*password\s+--encrypted\s+.*/) }
    end
  end
end
