# encoding: UTF-8

control "SV-217953" do
  title "The audit system must be configured to audit all attempts to alter system time through stime."
  desc "Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited."
  desc "default", "Arbitrary changes to the system time can be used to obfuscate
nefarious activities in log files, as well as to confuse network services that
are highly dependent upon an accurate system time (such as sshd). All changes
to the system time should be audited."
  desc "check", "If the system is 64-bit only, this is not applicable.

To determine if the system is configured to audit calls to the \"stime\" system call, run the following command:

$ sudo grep -w \"stime\" /etc/audit/audit.rules
-a always,exit -F arch=b32 -S stime -k audit_time_rules

If the system is not configured to audit the \"stime\" syscall, this is a finding."
  desc "fix", "Add the following to \"/etc/audit/audit.rules\": 

# audit_time_rules
-a always,exit -F arch=b32 -S stime -k audit_time_rules"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000062"
  tag gid: "V-217953"
  tag rid: "SV-217953r603264_rule"
  tag stig_id: "RHEL-06-000169"
  tag fix_id: "F-19432r376875_fix"
  tag cci: ["CCI-000169"]
  tag nist: ["AU-12 a", "Rev_4"]

  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-[Aa][\s]*(?:exit,always|always,exit)[\s]+-F[\s]+arch=b32.*(?:-S[\s]+|,)stime(?:[\s]+|,).*-k[\s]+[\S]+[\s]*$/) }
  end
end