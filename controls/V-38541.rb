control "V-38541" do
  title "The audit system must be configured to audit modifications to the
systems Mandatory Access Control (MAC) configuration (SELinux)."
  desc  "The system's mandatory access policy (SELinux) should not be
arbitrarily changed by anything other than administrator action. All changes to
MAC policy should be audited."
  impact 'low'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38541"
  tag "rid": "SV-50342r2_rule"
  tag "stig_id": "RHEL-06-000183"
  tag "fix_id": "F-43489r1_fix"
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
  desc 'check', "To determine if the system is configured to audit changes to
its SELinux configuration files, run the following command:

$ sudo grep -w \"/etc/selinux\" /etc/audit/audit.rules

If the system is configured to watch for changes to its SELinux configuration,
a line should be returned (including \"-p wa\" indicating permissions that are
watched).

If the system is not configured to audit attempts to change the MAC policy,
this is a finding."
  desc 'fix', "Add the following to \"/etc/audit/audit.rules\":

-w /etc/selinux/ -p wa -k MAC-policy"

  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\-w\s+\/etc\/selinux\/\s+\-p\s+wa\s+\-k\s+[-\w]+\s*$/) }
  end
end

