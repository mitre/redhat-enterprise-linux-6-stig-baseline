control "V-38671" do
  title "The sendmail package must be removed."
  desc  "The sendmail software was not developed with security in mind and its
design prevents it from being effectively contained by SELinux. Postfix should
be used instead."
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38671"
  tag "rid": "SV-50472r1_rule"
  tag "stig_id": "RHEL-06-000288"
  tag "fix_id": "F-43620r1_fix"
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
  desc 'check', "Run the following command to determine if the \"sendmail\"
package is installed:

# rpm -q sendmail


If the package is installed, this is a finding."
  desc 'fix', "Sendmail is not the default mail transfer agent and is not
installed by default. The \"sendmail\" package can be removed with the
following command:

# yum erase sendmail"

  describe package("sendmail") do
    it { should_not be_installed }
  end
end

