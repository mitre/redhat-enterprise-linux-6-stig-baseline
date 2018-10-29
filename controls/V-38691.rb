control "V-38691" do
  title "The Bluetooth service must be disabled."
  desc  "Disabling the \"bluetooth\" service prevents the system from
attempting connections to Bluetooth devices, which entails some security risk.
Nevertheless, variation in this risk decision may be expected due to the
utility of Bluetooth connectivity and its limited range."
  impact 0.5
  tag "gtitle": "SRG-OS-000034"
  tag "gid": "V-38691"
  tag "rid": "SV-50492r2_rule"
  tag "stig_id": "RHEL-06-000331"
  tag "fix_id": "F-43640r1_fix"
  tag "cci": ["CCI-000085"]
  tag "nist": ["AC-19 c", "Rev_4"]
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
  tag "check": "To check that the \"bluetooth\" service is disabled in system
boot configuration, run the following command:

# chkconfig \"bluetooth\" --list

Output should indicate the \"bluetooth\" service has either not been installed
or has been disabled at all runlevels, as shown in the example below:

# chkconfig \"bluetooth\" --list
\"bluetooth\" 0:off 1:off 2:off 3:off 4:off 5:off 6:off


If the service is configured to run, this is a finding."
  tag "fix": "The \"bluetooth\" service can be disabled with the following
command:

# chkconfig bluetooth off



# service bluetooth stop"

  describe service("bluetooth").runlevels(/0/) do
    it { should_not be_enabled }
  end
  describe service("bluetooth").runlevels(/1/) do
    it { should_not be_enabled }
  end
  describe service("bluetooth").runlevels(/2/) do
    it { should_not be_enabled }
  end
  describe service("bluetooth").runlevels(/3/) do
    it { should_not be_enabled }
  end
  describe service("bluetooth").runlevels(/4/) do
    it { should_not be_enabled }
  end
  describe service("bluetooth").runlevels(/5/) do
    it { should_not be_enabled }
  end
  describe service("bluetooth").runlevels(/6/) do
    it { should_not be_enabled }
  end
end

