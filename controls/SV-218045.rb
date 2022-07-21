# encoding: UTF-8

control "SV-218045" do
  title "Temporary accounts must be provisioned with an expiration date."
  desc "When temporary accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked."
  desc "default", "When temporary accounts are created, there is a risk they may remain
in place and active after the need for them no longer exists. Account
expiration greatly reduces the risk of accounts being misused or hijacked."
  desc "check", "For every temporary account, run the following command to obtain its account aging and expiration information: 

# chage -l [USER]

Verify each of these accounts has an expiration date set as documented. 
If any temporary accounts have no expiration date set or do not expire within a documented time frame, this is a finding."
  desc "fix", "In the event temporary accounts are required, configure the system to terminate them after a documented time period. For every temporary account, run the following command to set an expiration date on it, substituting \"[USER]\" and \"[YYYY-MM-DD]\" appropriately: 

# chage -E [YYYY-MM-DD] [USER]

\"[YYYY-MM-DD]\" indicates the documented expiration date for the account."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000002"
  tag gid: "V-218045"
  tag rid: "SV-218045r603264_rule"
  tag stig_id: "RHEL-06-000297"
  tag fix_id: "F-19524r377151_fix"
  tag cci: ["CCI-000016"]
  tag nist: ["AC-2 (2)", "Rev_4"]

  temporary_accounts = input('temporary_accounts')
  if temporary_accounts.empty?
    describe "Temporary accounts" do
      it { should_be empty }
    end
  else
    temporary_accounts.each do |acct|
      describe shadow.users(acct) do
        its('max_days.first.to_i') { should cmp <= input('temporary_accounts_expiration_days') }
      end
    end
  end
end