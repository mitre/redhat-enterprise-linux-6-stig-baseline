# encoding: UTF-8

control "SV-217888" do
  title "Users must not be able to change passwords more than once every 24 hours."
  desc "Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement."
  desc "default", "Setting the minimum password age protects against users cycling back
to a favorite password after satisfying the password reuse requirement."
  desc "check", "To check the minimum password age, run the command: 

$ grep PASS_MIN_DAYS /etc/login.defs

The DoD requirement is 1. 
If it is not set to the required value, this is a finding."
  desc "fix", "To specify password minimum age for new accounts, edit the file \"/etc/login.defs\" and add or correct the following line, replacing [DAYS] appropriately: 

PASS_MIN_DAYS [DAYS]

A value of 1 day is considered sufficient for many environments. The DoD requirement is 1."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000075"
  tag gid: "V-217888"
  tag rid: "SV-217888r603264_rule"
  tag stig_id: "RHEL-06-000051"
  tag fix_id: "F-19367r376680_fix"
  tag cci: ["CCI-000198"]
  tag nist: ["IA-5 (1) (d)", "Rev_4"]

  describe file("/etc/login.defs") do
    its("content") { should match(/^[\s]*PASS_MIN_DAYS[\s]+(\d+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^[\s]*PASS_MIN_DAYS[\s]+(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 1 }
    end
  end
end