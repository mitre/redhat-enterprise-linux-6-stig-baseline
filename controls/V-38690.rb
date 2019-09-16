control "V-38690" do
  title "Emergency accounts must be provisioned with an expiration date.
"
  desc  "When emergency accounts are created, there is a risk they may remain
in place and active after the need for them no longer exists. Account
expiration greatly reduces the risk of accounts being misused or hijacked."
  impact 0.3
  tag "gtitle": "SRG-OS-000123"
  tag "gid": "V-38690"
  tag "rid": "SV-50491r1_rule"
  tag "stig_id": "RHEL-06-000298"
  tag "fix_id": "F-43639r1_fix"
  tag "cci": ["CCI-001682"]
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
  tag "check": "For every emergency account, run the following command to
obtain its account aging and expiration information:

# chage -l [USER]

Verify each of these accounts has an expiration date set as documented.
If any emergency accounts have no expiration date set or do not expire within a
documented time frame, this is a finding."
  tag "fix": "In the event emergency accounts are required, configure the
system to terminate them after a documented time period. For every emergency
account, run the following command to set an expiration date on it,
substituting \"[USER]\" and \"[YYYY-MM-DD]\" appropriately:

# chage -E [YYYY-MM-DD] [USER]

\"[YYYY-MM-DD]\" indicates the documented expiration date for the account."

  emergency_accounts = attribute('emergency_accounts')

  if emergency_accounts.empty?
    describe "Emergency accounts" do
      it { should_be empty }
    end
  else
    emergency_accounts.each do |acct|
      describe command("chage -l #{acct} | grep 'Account expires'") do
        its('stdout.strip') { should_not match %r{:\s*never} }
      end
    end

    emergency_accounts.each do |acct|
      describe shadow.users(acct) do
        its('max_days.first.to_i') { should cmp <= attribute('emergency_accounts_expiration_days') }
      end
    end
  end
end

