# encoding: UTF-8

control "SV-218050" do
  title "The operating system must employ automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency."
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
  tag gid: "V-218050"
  tag rid: "SV-218050r603264_rule"
  tag stig_id: "RHEL-06-000304"
  tag fix_id: "F-19529r377166_fix"
  tag cci: ["CCI-001069", "CCI-001774"]
  tag nist: ["RA-5 (7)", "Rev_4", "CM-7 (5) (b)"]

  describe command('grep aide /etc/crontab /etc/cron.*/*') do
    its('stdout.strip') { should_not be_empty }
  end
end