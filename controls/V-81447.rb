control "V-81447" do
  title "The Red Hat Enterprise Linux operating system must mount /dev/shm with
the nosuid option."
  desc  "The \"nosuid\" mount option causes the system to not execute
\"setuid\" and \"setgid\" files with owner privileges. This option must be used
for mounting any file system not containing approved \"setuid\" and \"setguid\"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access."
  impact 0.3
  tag "gtitle": "SRG-OS-000368-GPOS-00154"
  tag "gid": "V-81447"
  tag "rid": "SV-96161r1_rule"
  tag "stig_id": "RHEL-06-000531"
  tag "fix_id": "F-88265r1_fix"
  tag "cci": ["CCI-001764"]
  tag "nist": ["CM-7 (2)", "Rev_4"]
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
  tag "check": "Verify that the \"nosuid\" option is configured for /dev/shm.

Check that the operating system is configured to use the \"nosuid\" option for
/dev/shm with the following command:

# cat /etc/fstab | grep /dev/shm | grep nosuid

tmpfs   /dev/shm   tmpfs   defaults,nodev,nosuid,noexec   0 0

If the \"nosuid\" option is not present on the line for \"/dev/shm\", this is a
finding.

Verify \"/dev/shm\" is mounted with the \"nosuid\" option:

# mount | grep \"/dev/shm\" | grep nosuid

If no results are returned, this is a finding."
  tag "fix": "Configure the \"/etc/fstab\" to use the \"nosuid\" option for all
lines containing \"/dev/shm\"."

  describe file("/etc/fstab") do
    its("content") { should match(/^[^#\s]+[ \t]+\/dev\/shm[ \t]+[\w\d]+[ \t]+([\w,]+)\s*.*$/) }
  end
  file("/etc/fstab").content.to_s.scan(/^[^#\s]+[ \t]+\/dev\/shm[ \t]+[\w\d]+[ \t]+([\w,]+)\s*.*$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:nosuid|[\w,]+,nosuid)(?:$|,[\w,]+$)/) }
    end
  end
  describe file("/etc/mtab") do
    its("content") { should match(/^[^#\s]+[ \t]+\/dev\/shm[ \t]+[\w\d]+[ \t]+([\w,]+)\s*.*$/) }
  end
  file("/etc/mtab").content.to_s.scan(/^[^#\s]+[ \t]+\/dev\/shm[ \t]+[\w\d]+[ \t]+([\w,]+)\s*.*$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:nosuid|[\w,]+,nosuid)(?:$|,[\w,]+$)/) }
    end
  end
end

