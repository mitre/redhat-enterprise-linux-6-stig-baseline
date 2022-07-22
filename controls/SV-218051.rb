# encoding: UTF-8

control "SV-218051" do
  title "The operating system must provide a near real-time alert when any of the organization defined list of compromise or potential compromise indicators occurs."
  desc "By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files."
  desc "default", "By default, AIDE does not install itself for periodic execution.
Periodically running AIDE may reveal unexpected changes in installed files."
  desc "check", "To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding."
  desc "fix", "AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000363"
  tag gid: "V-218051"
  tag rid: "SV-218051r603264_rule"
  tag stig_id: "RHEL-06-000305"
  tag fix_id: "F-19530r377169_fix"
  tag cci: ["CCI-001263", "CCI-001774"]
  tag nist: ["SI-4 (5)", "Rev_4", "CM-7 (5) (b)"]

  describe command('grep aide /etc/crontab /etc/cron.*/*') do
    its('stdout.strip') { should_not be_empty }
  end
end