control "V-38683" do
  title "All accounts on the system must have unique user or account names"
  desc  "Unique usernames allow for accountability on the system."
  impact 0.3
  tag "gtitle": "SRG-OS-000121"
  tag "gid": "V-38683"
  tag "rid": "SV-50484r1_rule"
  tag "stig_id": "RHEL-06-000296"
  tag "fix_id": "F-43632r1_fix"
  tag "cci": ["CCI-000804"]
  tag "nist": ["IA-8", "Rev_4"]
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
  tag "check": "Run the following command to check for duplicate account names:

# pwck -rq

If there are no duplicate names, no line will be returned.
If a line is returned, this is a finding."
  tag "fix": "Change usernames, or delete accounts, so each has a unique name."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

