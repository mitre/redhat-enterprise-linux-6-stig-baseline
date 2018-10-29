control "V-38461" do
  title "The /etc/group file must have mode 0644 or less permissive."
  desc  "The \"/etc/group\" file contains information regarding groups that are
configured on the system. Protection of this file is important for system
security."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38461"
  tag "rid": "SV-50261r1_rule"
  tag "stig_id": "RHEL-06-000044"
  tag "fix_id": "F-43406r1_fix"
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
  tag "check": "To check the permissions of \"/etc/group\", run the command:

$ ls -l /etc/group

If properly configured, the output should indicate the following permissions:
\"-rw-r--r--\"
If it does not, this is a finding."
  tag "fix": "To properly set the permissions of \"/etc/group\", run the
command:

# chmod 644 /etc/group"

  describe file("/etc/group") do
    it { should exist }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_writable.by "owner" }
  end
end

