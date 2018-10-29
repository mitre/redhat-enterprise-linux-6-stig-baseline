control "V-38656" do
  title "The system must use SMB client signing for connecting to samba servers
using smbclient."
  desc  "Packet signing can prevent man-in-the-middle attacks which modify SMB
packets in transit."
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38656"
  tag "rid": "SV-50457r1_rule"
  tag "stig_id": "RHEL-06-000272"
  tag "fix_id": "F-43606r1_fix"
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
  tag "check": "To verify that Samba clients running smbclient must use packet
signing, run the following command:

# grep signing /etc/samba/smb.conf

The output should show:

client signing = mandatory


If it is not, this is a finding."
  tag "fix": "To require samba clients running \"smbclient\" to use packet
signing, add the following to the \"[global]\" section of the Samba
configuration file in \"/etc/samba/smb.conf\":

client signing = mandatory

Requiring samba clients such as \"smbclient\" to use packet signing ensures
they can only communicate with servers that support packet signing."

  describe.one do
    describe package("samba-common") do
      it { should_not be_installed }
    end
    describe file("/etc/samba/smb.conf") do
      its("content") { should match(/^[\s]*client[\s]+signing[\s]*=[\s]*mandatory/) }
    end
  end
end

