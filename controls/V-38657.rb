control "V-38657" do
  title "The system must use SMB client signing for connecting to samba servers
using mount.cifs."
  desc  "Packet signing can prevent man-in-the-middle attacks which modify SMB
packets in transit."
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38657"
  tag "rid": "SV-50458r2_rule"
  tag "stig_id": "RHEL-06-000273"
  tag "fix_id": "F-43607r1_fix"
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
  tag "check": "If Samba is not in use, this is not applicable.

To verify that Samba clients using mount.cifs must use packet signing, run the
following command:

# grep sec /etc/fstab /etc/mtab

The output should show either \"krb5i\" or \"ntlmv2i\" in use.
If it does not, this is a finding."
  tag "fix": "Require packet signing of clients who mount Samba shares using
the \"mount.cifs\" program (e.g., those who specify shares in \"/etc/fstab\").
To do so, ensure signing options (either \"sec=krb5i\" or \"sec=ntlmv2i\") are
used.

See the \"mount.cifs(8)\" man page for more information. A Samba client should
only communicate with servers who can support SMB packet signing."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

