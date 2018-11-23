control "V-38584" do
  title "The xinetd service must be uninstalled if no network services
utilizing it are enabled."
  desc  "Removing the \"xinetd\" package decreases the risk of the xinetd
service's accidental (or intentional) activation."
  impact 'low'
  tag "gtitle": "SRG-OS-000096"
  tag "gid": "V-38584"
  tag "rid": "SV-50385r1_rule"
  tag "stig_id": "RHEL-06-000204"
  tag "fix_id": "F-43532r1_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
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
  desc 'check', "If network services are using the xinetd service, this is not
applicable.

Run the following command to determine if the \"xinetd\" package is installed:

# rpm -q xinetd


If the package is installed, this is a finding."
  desc 'fix', "The \"xinetd\" package can be uninstalled with the following
command:

# yum erase xinetd"

  describe package("xinetd") do
    it { should_not be_installed }
  end
end

