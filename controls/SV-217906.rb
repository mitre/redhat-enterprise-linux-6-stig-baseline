# encoding: UTF-8

control "SV-217906" do
  title "The system must not permit interactive boot."
  desc "Using interactive boot, the console user could disable auditing, firewalls, or other services, weakening system security."
  desc "default", "Using interactive boot, the console user could disable auditing,
firewalls, or other services, weakening system security."
  desc "check", "To check whether interactive boot is disabled, run the following command: 

$ grep PROMPT /etc/sysconfig/init

If interactive boot is disabled, the output will show: 

PROMPT=no


If it does not, this is a finding."
  desc "fix", "To disable the ability for users to perform interactive startups, edit the file \"/etc/sysconfig/init\". Add or correct the line: 

PROMPT=no

The \"PROMPT\" option allows the console user to perform an interactive system startup, in which it is possible to select the set of services which are started on boot."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000080"
  tag gid: "V-217906"
  tag rid: "SV-217906r603264_rule"
  tag stig_id: "RHEL-06-000070"
  tag fix_id: "F-19385r376734_fix"
  tag cci: ["CCI-000213"]
  tag nist: ["AC-3", "Rev_4"]

  describe file("/etc/sysconfig/init") do
    its("content") { should match(/^[\s]*PROMPT[\s]*=[\s]*no[\s]*$/) }
  end
end