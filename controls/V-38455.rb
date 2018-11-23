control "V-38455" do
  title "The system must use a separate file system for /tmp."
  desc  "The \"/tmp\" partition is used as temporary storage by many programs.
Placing \"/tmp\" in its own partition enables the setting of more restrictive
mount options, which can help protect programs which use it."
  impact 'low'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38455"
  tag "rid": "SV-50255r1_rule"
  tag "stig_id": "RHEL-06-000001"
  tag "fix_id": "F-43387r1_fix"
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
  desc 'check', "Run the following command to determine if \"/tmp\" is on its
own partition or logical volume:

$ mount | grep \"on /tmp \"

If \"/tmp\" has its own partition or volume group, a line will be returned.
If no line is returned, this is a finding."
  desc 'fix', "The \"/tmp\" directory is a world-writable directory used for
temporary file storage. Ensure it has its own partition or logical volume at
installation time, or migrate it using LVM."

  describe mount("/tmp") do
    it { should be_mounted }
  end
end

