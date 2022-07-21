# encoding: UTF-8

control "SV-217947" do
  title "The system must retain enough rotated audit logs to cover the required log retention period."
  desc "The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained."
  desc "default", "The total storage for audit log files must be large enough to retain
log information over the period required. This is a function of the maximum log
file size and the number of logs retained."
  desc "check", "Inspect \"/etc/audit/auditd.conf\" and locate the following line to determine how many logs the system is configured to retain after rotation: \"# grep num_logs /etc/audit/auditd.conf\" 

num_logs = 5


If the overall system log file(s) retention hasn't been properly set up, this is a finding."
  desc "fix", "Determine how many log files \"auditd\" should retain when it rotates logs. Edit the file \"/etc/audit/auditd.conf\". Add or modify the following line, substituting [NUMLOGS] with the correct value: 

num_logs = [NUMLOGS]

Set the value to 5 for general-purpose systems. Note that values less than 2 result in no log rotation."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217947"
  tag rid: "SV-217947r603264_rule"
  tag stig_id: "RHEL-06-000159"
  tag fix_id: "F-19426r376857_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^num_logs\s*=\s*(\d+)\s*$/) }
  end
  file("/etc/audit/auditd.conf").content.to_s.scan(/^num_logs\s*=\s*(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 5 }
    end
  end
end