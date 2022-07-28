# encoding: UTF-8

control "SV-217954" do
  title "The audit system must be configured to audit all attempts to alter system time through clock_settime."
  desc "Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited."
  desc "default", "Arbitrary changes to the system time can be used to obfuscate
nefarious activities in log files, as well as to confuse network services that
are highly dependent upon an accurate system time (such as sshd). All changes
to the system time should be audited."
  desc "check", "To determine if the system is configured to audit calls to the \"clock_settime\" system call, run the following command:

$ sudo grep -w \"clock_settime\" /etc/audit/audit.rules

-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules
-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules

If the system is 64-bit and does not return a rule for both \"b32\" and \"b64\" architectures, this is a finding.

If the system is not configured to audit the \"clock_settime\" syscall, this is a finding."
  desc "fix", "Add the following to \"/etc/audit/audit.rules\":

# audit_time_rules
-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules

If the system is 64-bit, then also add the following:  

# audit_time_rules
-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000062"
  tag gid: "V-217954"
  tag rid: "SV-217954r603264_rule"
  tag stig_id: "RHEL-06-000171"
  tag fix_id: "F-19433r376878_fix"
  tag cci: ["CCI-000169"]
  tag nist: ["AU-12 a", "Rev_4"]

  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-[Aa][\s]*(?:exit,always|always,exit)[\s]+-F[\s]+arch=b32.*(?:-S[\s]+|,)clock_settime(?:[\s]+|,).*-k[\s]+[\S]+[\s]*$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-[Aa][\s]*(?:exit,always|always,exit)[\s]+-F[\s]+arch=b64.*(?:-S[\s]+|,)clock_settime(?:[\s]+|,).*-k[\s]+[\S]+[\s]*$/) }
    end
  end
end