control "V-54381" do
  title "The audit system must switch the system to single-user mode when
available audit storage volume becomes dangerously low."
  desc  "Administrators should be made aware of an inability to record audit
records. If a separate partition or logical volume of adequate size is used,
running low on space for audit records should never occur. "
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-54381"
  tag "rid": "SV-68627r3_rule"
  tag "stig_id": "RHEL-06-000163"
  tag "fix_id": "F-59235r2_fix"
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
  desc 'check', "Inspect \"/etc/audit/auditd.conf\" and locate the following
line to determine if the system is configured to either suspend, switch to
single-user mode, or halt when disk space has run low:

admin_space_left_action = single

If the system is not configured to switch to single-user mode, suspend, or halt
for corrective action, this is a finding. "
  desc 'fix', "The \"auditd\" service can be configured to take an action when
disk space is running low but prior to running out of space completely. Edit
the file \"/etc/audit/auditd.conf\". Add or modify the following line,
substituting [ACTION] appropriately:

admin_space_left_action = [ACTION]

Set this value to \"single\" to cause the system to switch to single-user mode
for corrective action. Acceptable values also include \"suspend\" and \"halt\".
For certain systems, the need for availability outweighs the need to log all
actions, and a different setting should be determined. Details regarding all
possible values for [ACTION] are described in the \"auditd.conf\" man page. "

  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*admin_space_left_action[ ]+=[ ]+(\S+)\s*$/) }
  end
  file("/etc/audit/auditd.conf").content.to_s.scan(/^\s*admin_space_left_action[ ]+=[ ]+(\S+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:[sS][iI][nN][gG][lL][eE]|[sS][uU][sS][pP][eE][nN][dD]|[hH][aA][lL][tT])$/) }
    end
  end
end

