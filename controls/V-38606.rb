control "V-38606" do
  title "The tftp-server package must not be installed unless required."
  desc  "Removing the \"tftp-server\" package decreases the risk of the
accidental (or intentional) activation of tftp services."
  impact 0.5
  tag "gtitle": "SRG-OS-000095"
  tag "gid": "V-38606"
  tag "rid": "SV-50407r2_rule"
  tag "stig_id": "RHEL-06-000222"
  tag "fix_id": "F-43554r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  tag "check": "Run the following command to determine if the \"tftp-server\"
package is installed:

# rpm -q tftp-server


If the package is installed, this is a finding."
  tag "fix": "The \"tftp-server\" package can be removed with the following
command:

# yum erase tftp-server"

  describe package("tftp-server") do
    it { should_not be_installed }
  end
end

