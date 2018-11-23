control "V-38456" do
  title "The system must use a separate file system for /var."
  desc  "Ensuring that \"/var\" is mounted on its own partition enables the
setting of more restrictive mount options. This helps protect system services
such as daemons or other programs which use it. It is not uncommon for the
\"/var\" directory to contain world-writable directories, installed by other
software packages."
  impact 'low'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38456"
  tag "rid": "SV-50256r1_rule"
  tag "stig_id": "RHEL-06-000002"
  tag "fix_id": "F-43401r2_fix"
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
  desc 'check', "Run the following command to determine if \"/var\" is on its
own partition or logical volume:

$ mount | grep \"on /var \"

If \"/var\" has its own partition or volume group, a line will be returned.
If no line is returned, this is a finding."
  desc 'fix', "The \"/var\" directory is used by daemons and other system
services to store frequently-changing data. Ensure that \"/var\" has its own
partition or logical volume at installation time, or migrate it using LVM."

  describe mount("/var") do
    it { should be_mounted }
  end
end

