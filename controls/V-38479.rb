control "V-38479" do
  title "User passwords must be changed at least every 60 days."
  desc  "Setting the password maximum age ensures users are required to
periodically change their passwords. This could possibly decrease the utility
of a stolen password. Requiring shorter password lifetimes increases the risk
of users writing down the password in a convenient location subject to physical
compromise."
  impact 0.5
  tag "gtitle": "SRG-OS-000076"
  tag "gid": "V-38479"
  tag "rid": "SV-50279r1_rule"
  tag "stig_id": "RHEL-06-000053"
  tag "fix_id": "F-43424r1_fix"
  tag "cci": ["CCI-000199"]
  tag "nist": ["IA-5 (1) (d)", "Rev_4"]
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
  tag "check": "To check the maximum password age, run the command:

$ grep PASS_MAX_DAYS /etc/login.defs

The DoD requirement is 60.
If it is not set to the required value, this is a finding."
  tag "fix": "To specify password maximum age for new accounts, edit the file
\"/etc/login.defs\" and add or correct the following line, replacing [DAYS]
appropriately:

PASS_MAX_DAYS [DAYS]

The DoD requirement is 60."

  describe file("/etc/login.defs") do
    its("content") { should match(/^[\s]*PASS_MAX_DAYS[\s]+(\d+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^[\s]*PASS_MAX_DAYS[\s]+(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 60 }
    end
  end
end

