# encoding: UTF-8

control "SV-217890" do
  title "Users must be warned 7 days in advance of password expiration."
  desc "Setting the password warning age enables users to make the change at a practical time."
  desc "default", "Setting the password warning age enables users to make the change at a
practical time."
  desc "check", "To check the password warning age, run the command: 

$ grep PASS_WARN_AGE /etc/login.defs

The DoD requirement is 7. 
If it is not set to the required value, this is a finding."
  desc "fix", "To specify how many days prior to password expiration that a warning will be issued to users, edit the file \"/etc/login.defs\" and add or correct the following line, replacing [DAYS] appropriately: 

PASS_WARN_AGE [DAYS]

The DoD requirement is 7."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217890"
  tag rid: "SV-217890r603264_rule"
  tag stig_id: "RHEL-06-000054"
  tag fix_id: "F-19369r376686_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/login.defs") do
    its("content") { should match(/^[\s]*PASS_WARN_AGE[\s]*(\d+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^[\s]*PASS_WARN_AGE[\s]*(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 7 }
    end
  end
end