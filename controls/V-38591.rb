control "V-38591" do
  title "The rsh-server package must not be installed."
  desc  "The \"rsh-server\" package provides several obsolete and insecure
network services. Removing it decreases the risk of those services' accidental
(or intentional) activation."
  impact 0.7
  tag "gtitle": "SRG-OS-000095"
  tag "gid": "V-38591"
  tag "rid": "SV-50392r1_rule"
  tag "stig_id": "RHEL-06-000213"
  tag "fix_id": "F-43539r1_fix"
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
  tag "check": "Run the following command to determine if the \"rsh-server\"
package is installed:

# rpm -q rsh-server


If the package is installed, this is a finding."
  tag "fix": "The \"rsh-server\" package can be uninstalled with the following
command:

# yum erase rsh-server"

  describe package("rsh-server") do
    it { should_not be_installed }
  end
end

