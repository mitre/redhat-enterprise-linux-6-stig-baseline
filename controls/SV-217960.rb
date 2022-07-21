# encoding: UTF-8

control "SV-217960" do
  title "The audit system must be configured to audit modifications to the systems network configuration."
  desc "The network environment should not be modified by anything other than administrator action. Any change to network parameters should be audited."
  desc "default", "The network environment should not be modified by anything other than
administrator action. Any change to network parameters should be audited."
  desc "check", "If you are running x86_64 architecture, determine the values for sethostname:

$ uname -m; ausyscall i386 sethostname; ausyscall x86_64 sethostname
      
If the values returned are not identical verify that the system is configured to monitor network configuration changes for the i386 and x86_64 architectures:

$ sudo egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules

-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications

If the system is 64-bit and does not return a rule for both \"b32\" and \"b64\" architectures, this is a finding.

If the system is not configured to audit changes of the network configuration, this is a finding."
  desc "fix", "Add the following to \"/etc/audit/audit.rules\":

# audit_network_modifications
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications   

If the system is 64-bit, then also add the following:

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217960"
  tag rid: "SV-217960r603264_rule"
  tag stig_id: "RHEL-06-000182"
  tag fix_id: "F-19439r376896_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  both_archs = command("ausyscall i386 sethostname").stdout.strip != command("ausyscall x86_64 sethostname").stdout.strip
  if os.arch == 'x86_64' or both_archs
    describe command("egrep -w '^[^\#]*sethostname' /etc/audit/audit.rules | grep 'arch=b64'") do
      its('stdout.strip') { should_not be_empty }
    end
    describe command("egrep -w '^[^\#]*setdomainname' /etc/audit/audit.rules | grep 'arch=b64'") do
      its('stdout.strip') { should_not be_empty }
    end
  end
  if os.arch != 'x86_64' or both_archs
    describe command("egrep -w '^[^\#]*sethostname' /etc/audit/audit.rules | grep 'arch=b32'") do
      its('stdout.strip') { should_not be_empty }
    end
    describe command("egrep -w '^[^\#]*setdomainname' /etc/audit/audit.rules | grep 'arch=b32'") do
      its('stdout.strip') { should_not be_empty }
    end
  end
  describe command("egrep '^\\s*\\-w /etc/issue \\-p wa' /etc/audit/audit.rules") do
    its('stdout.strip') { should_not be_empty }
  end
  describe command("egrep '^\\s*\\-w /etc/issue.net \\-p wa' /etc/audit/audit.rules") do
    its('stdout.strip') { should_not be_empty }
  end
  describe command("egrep '^\\s*\\-w /etc/hosts \\-p wa' /etc/audit/audit.rules") do
    its('stdout.strip') { should_not be_empty }
  end
  describe command("egrep '^\\s*\\-w /etc/sysconfig/network \\-p wa' /etc/audit/audit.rules") do
    its('stdout.strip') { should_not be_empty }
  end
end