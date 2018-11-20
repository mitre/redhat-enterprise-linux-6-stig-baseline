control "V-38438" do
  title "Auditing must be enabled at boot by setting a kernel parameter."
  desc  "Each process on the system carries an \"auditable\" flag which
indicates whether its activities can be audited. Although \"auditd\" takes care
of enabling this for all processes which launch after it does, adding the
kernel argument ensures it is set for every process during boot."
  impact 0.3
  tag "gtitle": "SRG-OS-000062"
  tag "gid": "V-38438"
  tag "rid": "SV-50238r4_rule"
  tag "stig_id": "RHEL-06-000525"
  tag "fix_id": "F-43382r4_fix"
  tag "cci": ["CCI-000169"]
  tag "nist": ["AU-12 a", "Rev_4"]
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
  tag "check": "Inspect the kernel boot arguments (which follow the word
\"kernel\") in \"/boot/grub/grub.conf\". If they include \"audit=1\", then
auditing is enabled at boot time.

If auditing is not enabled at boot time, this is a finding.

If the system uses UEFI inspect the kernel boot arguments (which follow the
word \"kernel\") in \"/boot/efi/EFI/redhat/grub.conf\". If they include
\"audit=1\", then auditing is enabled at boot time."
  tag "fix": "To ensure all processes can be audited, even those which start
prior to the audit daemon, add the argument \"audit=1\" to the kernel line in
\"/boot/grub/grub.conf\" or \"/boot/efi/EFI/redhat/grub.conf\", in the manner
below:

kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet
audit=1

UEFI systems may prepend \"/boot\" to the \"/vmlinuz-version\" argument."

  describe.one do
    describe file("/boot/grub/grub.conf") do
      its("content") { should match(/^\s*kernel\s(?:\/boot)?\/vmlinuz.*audit=1.*$/) }
    end
    describe file("/boot/efi/EFI/redhat/grub.conf") do
      its("content") { should match(/^\s*kernel\s(?:\/boot)?\/vmlinuz.*audit=1.*$/) }
    end
  end
end

