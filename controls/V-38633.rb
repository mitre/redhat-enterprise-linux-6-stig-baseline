control 'V-38633' do
  title 'The system must set a maximum audit log file size.'
  desc  "The total storage for audit log files must be large enough to retain
log information over the period required. This is a function of the maximum log
file size and the number of logs retained."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38633'
  tag "rid": 'SV-50434r1_rule'
  tag "stig_id": 'RHEL-06-000160'
  tag "fix_id": 'F-43582r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "Inspect \"/etc/audit/auditd.conf\" and locate the following
line to determine how much data the system will retain in each audit log file:
\"# grep max_log_file /etc/audit/auditd.conf\"

max_log_file = 6


If the system audit data threshold hasn't been properly set up, this is a
finding."
  tag "fix": "Determine the amount of audit data (in megabytes) which should be
retained in each log file. Edit the file \"/etc/audit/auditd.conf\". Add or
modify the following line, substituting the correct value for [STOREMB]:

max_log_file = [STOREMB]

Set the value to \"6\" (MB) or higher for general-purpose systems. Larger
values, of course, support retention of even more audit data."

  describe file('/etc/audit/auditd.conf') do
    its('content') { should match(/^max_log_file\s*=\s*(\d+)\s*$/) }
  end
  file('/etc/audit/auditd.conf').content.to_s.scan(/^max_log_file\s*=\s*(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 6 }
    end
  end
end
