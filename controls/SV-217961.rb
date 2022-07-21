# encoding: UTF-8

control "SV-217961" do
  title "The audit system must be configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux)."
  desc "The system's mandatory access policy (SELinux) should not be arbitrarily changed by anything other than administrator action. All changes to MAC policy should be audited."
  desc "default", "The system's mandatory access policy (SELinux) should not be
arbitrarily changed by anything other than administrator action. All changes to
MAC policy should be audited."
  desc "check", "To determine if the system is configured to audit changes to its SELinux configuration files, run the following command: 

$ sudo grep -w \"/etc/selinux\" /etc/audit/audit.rules

If the system is configured to watch for changes to its SELinux configuration, a line should be returned (including \"-p wa\" indicating permissions that are watched). 

If the system is not configured to audit attempts to change the MAC policy, this is a finding."
  desc "fix", "Add the following to \"/etc/audit/audit.rules\": 

-w /etc/selinux/ -p wa -k MAC-policy"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217961"
  tag rid: "SV-217961r603264_rule"
  tag stig_id: "RHEL-06-000183"
  tag fix_id: "F-19440r376899_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^\-w\s+\/etc\/selinux\/\s+\-p\s+wa\s+\-k\s+[-\w]+\s*$/) }
  end
end