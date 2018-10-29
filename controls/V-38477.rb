control "V-38477" do
  title "Users must not be able to change passwords more than once every 24
hours."
  desc  "Setting the minimum password age protects against users cycling back
to a favorite password after satisfying the password reuse requirement."
  impact 0.5
  tag "gtitle": "SRG-OS-000075"
  tag "gid": "V-38477"
  tag "rid": "SV-50277r1_rule"
  tag "stig_id": "RHEL-06-000051"
  tag "fix_id": "F-43422r1_fix"
  tag "cci": ["CCI-000198"]
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
  tag "check": "To check the minimum password age, run the command:

$ grep PASS_MIN_DAYS /etc/login.defs

The DoD requirement is 1.
If it is not set to the required value, this is a finding."
  tag "fix": "To specify password minimum age for new accounts, edit the file
\"/etc/login.defs\" and add or correct the following line, replacing [DAYS]
appropriately:

PASS_MIN_DAYS [DAYS]

A value of 1 day is considered sufficient for many environments. The DoD
requirement is 1."

  describe file("/etc/login.defs") do
    its("content") { should match(/^[\s]*PASS_MIN_DAYS[\s]+(\d+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^[\s]*PASS_MIN_DAYS[\s]+(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 1 }
    end
  end
end

