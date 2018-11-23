control "V-38449" do
  title "The /etc/gshadow file must have mode 0000."
  desc  "The /etc/gshadow file contains group password hashes. Protection of
this file is critical for system security."
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38449"
  tag "rid": "SV-50249r1_rule"
  tag "stig_id": "RHEL-06-000038"
  tag "fix_id": "F-43394r1_fix"
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
  desc 'check', "To check the permissions of \"/etc/gshadow\", run the command:

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following permissions:
\"----------\"
If it does not, this is a finding."
  desc 'fix', "To properly set the permissions of \"/etc/gshadow\", run the
command:

# chmod 0000 /etc/gshadow"

  describe file("/etc/gshadow") do
    it { should exist }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/gshadow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_setgid }
  end
  describe file("/etc/gshadow") do
    it { should_not be_sticky }
  end
  describe file("/etc/gshadow") do
    it { should_not be_setuid }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "owner" }
  end
  describe file("/etc/gshadow") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "owner" }
  end
end

