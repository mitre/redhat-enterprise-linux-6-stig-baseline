control "V-38458" do
  title "The /etc/group file must be owned by root."
  desc  "The \"/etc/group\" file contains information regarding groups that are
configured on the system. Protection of this file is important for system
security."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38458"
  tag "rid": "SV-50258r1_rule"
  tag "stig_id": "RHEL-06-000042"
  tag "fix_id": "F-43403r1_fix"
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
  tag "check": "To check the ownership of \"/etc/group\", run the command:

$ ls -l /etc/group

If properly configured, the output should indicate the following owner:
\"root\"
If it does not, this is a finding."
  tag "fix": "To properly set the owner of \"/etc/group\", run the command:

# chown root /etc/group"

  describe file("/etc/group") do
    it { should exist }
  end
  describe file("/etc/group") do
    its("uid") { should cmp 0 }
  end
end

