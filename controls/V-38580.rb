control "V-38580" do
  title "The audit system must be configured to audit the loading and unloading
of dynamic kernel modules."
  desc  "The addition/removal of kernel modules can be used to alter the
behavior of the kernel and potentially introduce malicious code into kernel
space. It is important to have an audit trail of modules that have been
introduced into the kernel."
  impact 'medium'
  tag "gtitle": "SRG-OS-000064"
  tag "gid": "V-38580"
  tag "rid": "SV-50381r2_rule"
  tag "stig_id": "RHEL-06-000202"
  tag "fix_id": "F-43528r2_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
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
  desc 'check', "To determine if the system is configured to audit execution of
module management programs, run the following commands:

$ sudo egrep -e \"(-w |-F path=)/sbin/insmod\" /etc/audit/audit.rules
$ sudo egrep -e \"(-w |-F path=)/sbin/rmmod\" /etc/audit/audit.rules
$ sudo egrep -e \"(-w |-F path=)/sbin/modprobe\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

To determine if the system is configured to audit calls to the \"init_module\"
system call, run the following command:

$ sudo grep -w \"init_module\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

To determine if the system is configured to audit calls to the
\"delete_module\" system call, run the following command:

$ sudo grep -w \"delete_module\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

If no line is returned for any of these commands, this is a finding. "
  desc 'fix', "Add the following to \"/etc/audit/audit.rules\" in order to
capture kernel module loading and unloading events, setting ARCH to either b32
or b64 as appropriate for your system:

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=[ARCH] -S init_module -S delete_module -k modules"

  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^(?:-w\s+|-a\s+(?:always,exit|exit,always)\s+-F\s+path=)\/sbin\/insmod\s+-p\s+[rwa]*x[rwa]*\s+-k\s+\S+\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^(?:-w\s+|-a\s+(?:always,exit|exit,always)\s+-F\s+path=)\/sbin\/rmmod\s+-p\s+[rwa]*x[rwa]*\s+-k\s+\S+\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^(?:-w\s+|-a\s+(?:always,exit|exit,always)\s+-F\s+path=)\/sbin\/modprobe\s+-p\s+[rwa]*x[rwa]*\s+-k\s+\S+\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^[\s]*-a[\s](?:always,exit|exit,always)+(?:.*-F[\s]+arch=b32\s+).*(?:,|-S\s+)delete_module(?:,|\s+).*-k\s+\S+\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^[\s]*-a[\s](?:always,exit|exit,always)(?:.*-F[\s]+arch=b32\s+).*(?:,|-S\s+)init_module(?:,|\s+).*-k\s+\S+\s*$/) }
  end
  describe.one do
    
  end
end

