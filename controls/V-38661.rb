control "V-38661" do
  title "The operating system must protect the confidentiality and integrity of
data at rest. "
  desc  "The risk of a system's physical compromise, particularly mobile
systems such as laptops, places its data at risk of compromise. Encrypting this
data mitigates the risk of its loss if the system is lost."
  impact 0.3
  tag "gtitle": "SRG-OS-000185"
  tag "gid": "V-38661"
  tag "rid": "SV-50462r2_rule"
  tag "stig_id": "RHEL-06-000276"
  tag "fix_id": "F-43610r3_fix"
  tag "cci": ["CCI-001199"]
  tag "nist": ["SC-28", "Rev_4"]
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
  tag "check": "Determine if encryption must be used to protect data on the
system.
If encryption must be used and is not employed, this is a finding."
  tag "fix": "Red Hat Enterprise Linux 6 natively supports partition encryption
through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The
easiest way to encrypt a partition is during installation time.

For manual installations, select the \"Encrypt\" checkbox during partition
creation to encrypt the partition. When this option is selected the system will
prompt for a passphrase to use in decrypting the partition. The passphrase will
subsequently need to be entered manually every time the system boots.

For automated/unattended installations, it is possible to use Kickstart by
adding the \"--encrypted\" and \"--passphrase=\" options to the definition of
each partition to be encrypted. For example, the following line would encrypt
the root partition:

part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted
--passphrase=[PASSPHRASE]

Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart
must then be protected accordingly. Omitting the \"--passphrase=\" option from
the partition definition will cause the installer to pause and interactively
ask for the passphrase during installation.

Detailed information on encrypting partitions using LUKS can be found on the
Red Hat Documentation web site:

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html"

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

