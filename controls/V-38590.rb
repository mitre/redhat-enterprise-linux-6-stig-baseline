control "V-38590" do
  title "The system must allow locking of the console screen in text mode."
  desc  "Installing \"screen\" ensures a console locking capability is
available for users who may need to suspend console logins."
  impact 'low'
  tag "gtitle": "SRG-OS-000030"
  tag "gid": "V-38590"
  tag "rid": "SV-50391r1_rule"
  tag "stig_id": "RHEL-06-000071"
  tag "fix_id": "F-43538r1_fix"
  tag "cci": ["CCI-000058"]
  tag "nist": ["AC-11 a", "Rev_4"]
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
  desc 'check', "Run the following command to determine if the \"screen\"
package is installed:

# rpm -q screen


If the package is not installed, this is a finding."
  desc 'fix', "To enable console screen locking when in text mode, install the
\"screen\" package:

# yum install screen

Instruct users to begin new terminal sessions with the following command:

$ screen

The console can now be locked with the following key combination:

ctrl+a x"

  describe package("screen") do
    it { should be_installed }
  end
end

