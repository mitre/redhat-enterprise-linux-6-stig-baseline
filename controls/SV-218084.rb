# encoding: UTF-8

control "SV-218084" do
  title "Audit log files must have mode 0640 or less permissive."
  desc "If users can write to audit logs, audit trails can be modified or destroyed."
  desc "default", "If users can write to audit logs, audit trails can be modified or
destroyed."
  desc "check", "Run the following command to check the mode of the system audit logs: 

grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %a:%n

Audit logs must be mode 0640 or less permissive. 
If any are more permissive, this is a finding."
  desc "fix", "Change the mode of the audit log files with the following command: 

# chmod 0640 [audit_file]"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000058"
  tag gid: "V-218084"
  tag rid: "SV-218084r603264_rule"
  tag stig_id: "RHEL-06-000383"
  tag fix_id: "F-19563r377268_fix"
  tag cci: ["CCI-000163"]
  tag nist: ["AU-9", "Rev_4", "AU-9 a"]

  describe command("find /var/log/audit -regex .\\*/\\^.\\*\\$ -perm -07137 -xdev") do
    its("stdout") { should be_empty }
  end
end