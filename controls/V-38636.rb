control "V-38636" do
  title "The system must retain enough rotated audit logs to cover the required
log retention period."
  desc  "The total storage for audit log files must be large enough to retain
log information over the period required. This is a function of the maximum log
file size and the number of logs retained."
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38636"
  tag "rid": "SV-50437r1_rule"
  tag "stig_id": "RHEL-06-000159"
  tag "fix_id": "F-43585r1_fix"
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
line to determine how many logs the system is configured to retain after
rotation: \"# grep num_logs /etc/audit/auditd.conf\"

num_logs = 5


If the overall system log file(s) retention hasn't been properly set up, this
is a finding."
  desc 'fix', "Determine how many log files \"auditd\" should retain when it
rotates logs. Edit the file \"/etc/audit/auditd.conf\". Add or modify the
following line, substituting [NUMLOGS] with the correct value:

num_logs = [NUMLOGS]

Set the value to 5 for general-purpose systems. Note that values less than 2
result in no log rotation."

  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^num_logs\s*=\s*(\d+)\s*$/) }
  end
  file("/etc/audit/auditd.conf").content.to_s.scan(/^num_logs\s*=\s*(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 5 }
    end
  end
end

