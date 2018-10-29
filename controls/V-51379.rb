control "V-51379" do
  title "All device files must be monitored by the system Linux Security
Module."
  desc  "If a device file carries the SELinux type \"unlabeled_t\", then
SELinux cannot properly restrict access to the device file. "
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-51379"
  tag "rid": "SV-65589r1_rule"
  tag "stig_id": "RHEL-06-000025"
  tag "fix_id": "F-56179r1_fix"
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
  tag "check": "To check for unlabeled device files, run the following command:

# ls -RZ /dev | grep unlabeled_t

It should produce no output in a well-configured system.

If there is output, this is a finding. "
  tag "fix": "Device files, which are used for communication with important
system resources, should be labeled with proper SELinux types. If any device
files carry the SELinux type \"unlabeled_t\", investigate the cause and correct
the file's context. "

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

