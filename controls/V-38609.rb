control "V-38609" do
  title "The TFTP service must not be running."
  desc  "Disabling the \"tftp\" service ensures the system is not acting as a
tftp server, which does not provide encryption or authentication."
  impact 0.5
  tag "gtitle": "SRG-OS-000248"
  tag "gid": "V-38609"
  tag "rid": "SV-50410r2_rule"
  tag "stig_id": "RHEL-06-000223"
  tag "fix_id": "F-43557r4_fix"
  tag "cci": ["CCI-001436"]
  tag "nist": ["AC-17 (8)", "Rev_4"]
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
  tag "check": "To check that the \"tftp\" service is disabled in system boot
configuration, run the following command:

# chkconfig \"tftp\" --list

Output should indicate the \"tftp\" service has either not been installed, or
has been disabled, as shown in the example below:

# chkconfig \"tftp\" --list
tftp off
OR
error reading information on service tftp: No such file or directory


If the service is running, this is a finding."
  tag "fix": "The \"tftp\" service should be disabled. The \"tftp\" service can
be disabled with the following command:

# chkconfig tftp off"

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

