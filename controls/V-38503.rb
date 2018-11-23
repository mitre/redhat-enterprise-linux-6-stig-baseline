control "V-38503" do
  title "The /etc/shadow file must be group-owned by root."
  desc  "The \"/etc/shadow\" file stores password hashes. Protection of this
file is critical for system security."
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38503"
  tag "rid": "SV-50304r1_rule"
  tag "stig_id": "RHEL-06-000034"
  tag "fix_id": "F-43450r1_fix"
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
  desc 'check', "To check the group ownership of \"/etc/shadow\", run the
command:

$ ls -l /etc/shadow

If properly configured, the output should indicate the following group-owner.
\"root\"
If it does not, this is a finding."
  desc 'fix', "To properly set the group owner of \"/etc/shadow\", run the
command:

# chgrp root /etc/shadow"

  describe file("/etc/shadow") do
    it { should exist }
  end
  describe file("/etc/shadow") do
    its("gid") { should cmp 0 }
  end
end

