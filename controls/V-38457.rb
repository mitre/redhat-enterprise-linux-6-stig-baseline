control "V-38457" do
  title "The /etc/passwd file must have mode 0644 or less permissive."
  desc  "If the \"/etc/passwd\" file is writable by a group-owner or the world
the risk of its compromise is increased. The file contains the list of accounts
on the system and associated information, and protection of this file is
critical for system security."
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38457"
  tag "rid": "SV-50257r1_rule"
  tag "stig_id": "RHEL-06-000041"
  tag "fix_id": "F-43397r1_fix"
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
  desc 'check', "To check the permissions of \"/etc/passwd\", run the command:

$ ls -l /etc/passwd

If properly configured, the output should indicate the following permissions:
\"-rw-r--r--\"
If it does not, this is a finding."
  desc 'fix', "To properly set the permissions of \"/etc/passwd\", run the
command:

# chmod 0644 /etc/passwd"

  describe file("/etc/passwd") do
    it { should exist }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/passwd") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should_not be_setgid }
  end
  describe file("/etc/passwd") do
    it { should_not be_sticky }
  end
  describe file("/etc/passwd") do
    it { should_not be_setuid }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/passwd") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/passwd") do
    it { should be_writable.by "owner" }
  end
end

