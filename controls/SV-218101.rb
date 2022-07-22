# encoding: UTF-8

control "SV-218101" do
  title "Audit log files must be group-owned by root."
  desc "If non-privileged users can write to audit logs, audit trails can be modified or destroyed."
  desc "default", "If non-privileged users can write to audit logs, audit trails can be
modified or destroyed."
  desc "check", "Run the following command to check the group owner of the system audit logs: 

grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %G:%n

Audit logs must be group-owned by root. 
If they are not, this is a finding."
  desc "fix", "Change the group owner of the audit log files with the following command: 

# chgrp root [audit_file]"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000057"
  tag gid: "V-218101"
  tag rid: "SV-218101r603264_rule"
  tag stig_id: "RHEL-06-000522"
  tag fix_id: "F-19580r377319_fix"
  tag cci: ["CCI-000162"]
  tag nist: ["AU-9", "Rev_4", "AU-9 a"]

  describe command("grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %G:%n") do
    its('stdout.lines') { should all match %{^root:} }
  end
end