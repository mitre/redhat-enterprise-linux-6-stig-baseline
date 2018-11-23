control "V-38463" do
  title "The system must use a separate file system for /var/log."
  desc  "Placing \"/var/log\" in its own partition enables better separation
between log files and other files in \"/var/\"."
  impact 'low'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38463"
  tag "rid": "SV-50263r1_rule"
  tag "stig_id": "RHEL-06-000003"
  tag "fix_id": "F-43408r1_fix"
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
  desc 'check', "Run the following command to determine if \"/var/log\" is on
its own partition or logical volume:

$ mount | grep \"on /var/log \"

If \"/var/log\" has its own partition or volume group, a line will be returned.
If no line is returned, this is a finding."
  desc 'fix', "System logs are stored in the \"/var/log\" directory. Ensure that
it has its own partition or logical volume at installation time, or migrate it
using LVM."

  describe mount("/var/log") do
    it { should be_mounted }
  end
end

