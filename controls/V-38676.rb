control "V-38676" do
  title "The xorg-x11-server-common (X Windows) package must not be installed,
unless required."
  desc  "Unnecessary packages should not be installed to decrease the attack
surface of the system."
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38676"
  tag "rid": "SV-50477r2_rule"
  tag "stig_id": "RHEL-06-000291"
  tag "fix_id": "F-43625r1_fix"
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
  tag "check": "To ensure the X Windows package group is removed, run the
following command:

$ rpm -qi xorg-x11-server-common

The output should be:

package xorg-x11-server-common is not installed


If it is not, this is a finding."
  tag "fix": "Removing all packages which constitute the X Window System
ensures users or malicious software cannot start X. To do so, run the following
command:

# yum groupremove \"X Window System\""

  describe package("xorg-x11-server-common") do
    it { should_not be_installed }
  end
end

