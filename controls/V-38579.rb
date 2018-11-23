control "V-38579" do
  title "The system boot loader configuration file(s) must be owned by root."
  desc  "Only root should be able to modify important boot parameters."
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38579"
  tag "rid": "SV-50380r2_rule"
  tag "stig_id": "RHEL-06-000065"
  tag "fix_id": "F-43527r2_fix"
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
  desc 'check', "To check the ownership of \"/boot/grub/grub.conf\", run the
command:

$ ls -lL /boot/grub/grub.conf

If properly configured, the output should indicate that the owner is \"root\".
If it does not, this is a finding."
  desc 'fix', "The file \"/boot/grub/grub.conf\" should be owned by the \"root\"
user to prevent destruction or modification of the file. To properly set the
owner of \"/boot/grub/grub.conf\", run the command:

# chown root /boot/grub/grub.conf"

  describe.one do
    describe file("/boot/grub/grub.conf") do
      it { should exist }
    end
    describe file("/boot/grub/grub.conf") do
      its("uid") { should cmp 0 }
    end
    describe file("/boot/efi/EFI/redhat/grub.conf") do
      it { should exist }
    end
    describe file("/boot/efi/EFI/redhat/grub.conf") do
      its("uid") { should cmp 0 }
    end
  end
end

