control "V-38685" do
  title "Temporary accounts must be provisioned with an expiration date."
  desc  "When temporary accounts are created, there is a risk they may remain
in place and active after the need for them no longer exists. Account
expiration greatly reduces the risk of accounts being misused or hijacked."
  impact 0.3
  tag "gtitle": "SRG-OS-000002"
  tag "gid": "V-38685"
  tag "rid": "SV-50486r1_rule"
  tag "stig_id": "RHEL-06-000297"
  tag "fix_id": "F-43634r1_fix"
  tag "cci": ["CCI-000016"]
  tag "nist": ["AC-2 (2)", "Rev_4"]
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
  tag "check": "For every temporary account, run the following command to
obtain its account aging and expiration information:

# chage -l [USER]

Verify each of these accounts has an expiration date set as documented.
If any temporary accounts have no expiration date set or do not expire within a
documented time frame, this is a finding."
  tag "fix": "In the event temporary accounts are required, configure the
system to terminate them after a documented time period. For every temporary
account, run the following command to set an expiration date on it,
substituting \"[USER]\" and \"[YYYY-MM-DD]\" appropriately:

# chage -E [YYYY-MM-DD] [USER]

\"[YYYY-MM-DD]\" indicates the documented expiration date for the account."

  temporary_accounts = attribute('temporary_accounts')

  if temporary_accounts.empty?
    describe "Temporary accounts" do
      it { should_be empty }
    end
  else
    temporary_accounts.each do |acct|
      describe shadow.users(acct) do
        its('max_days.first.to_i') { should cmp <= attribute('temporary_accounts_expiration_days') }
      end
    end
  end
end

