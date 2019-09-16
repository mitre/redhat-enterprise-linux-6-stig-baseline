control "V-38476" do
  title "Vendor-provided cryptographic certificates must be installed to verify
the integrity of system software."
  desc  "The Red Hat GPG keys are necessary to cryptographically verify
packages are from Red Hat. "
  impact 0.7
  tag "gtitle": "SRG-OS-000090"
  tag "gid": "V-38476"
  tag "rid": "SV-50276r3_rule"
  tag "stig_id": "RHEL-06-000008"
  tag "fix_id": "F-43421r3_fix"
  tag "cci": ["CCI-000352"]
  tag "nist": ["CM-5 (3)", "Rev_4"]
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
  tag "check": "To ensure that the GPG keys are installed, run:

$ rpm -q gpg-pubkey

The command should return the strings below:

gpg-pubkey-fd431d51-4ae0493b
gpg-pubkey-2fa658e0-45700c69

If the Red Hat GPG Keys are not installed, this is a finding."
  tag "fix": "To ensure the system can cryptographically verify base software
packages come from Red Hat (and to connect to the Red Hat Network to receive
them), the Red Hat GPG keys must be installed properly. To install the Red Hat
GPG keys, run:

# rhn_register

If the system is not connected to the Internet or an RHN Satellite, then
install the Red Hat GPG keys from trusted media such as the Red Hat
installation CD-ROM or DVD. Assuming the disc is mounted in \"/media/cdrom\",
use the following command as the root user to import them into the keyring:

# rpm --import /media/cdrom/RPM-GPG-KEY"

  keys = input('package_signing_keys')

  describe command('rpm -q gpg-pubkey') do
    keys.each do |key|
      its('stdout.strip') { should match key }
    end
  end
end

