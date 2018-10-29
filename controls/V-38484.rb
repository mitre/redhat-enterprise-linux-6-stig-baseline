control "V-38484" do
  title "The operating system, upon successful logon, must display to the user
the date and time of the last logon or access via ssh."
  desc  "Users need to be aware of activity that occurs regarding their
account. Providing users with information regarding the date and time of their
last successful login allows the user to determine if any unauthorized activity
has occurred and gives them an opportunity to notify administrators.

    At ssh login, a user must be presented with the last successful login date
and time.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000025"
  tag "gid": "V-38484"
  tag "rid": "SV-50285r2_rule"
  tag "stig_id": "RHEL-06-000507"
  tag "fix_id": "F-43431r2_fix"
  tag "cci": ["CCI-000052"]
  tag "nist": ["AC-9", "Rev_4"]
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
  tag "check": "Verify the value associated with the \"PrintLastLog\" keyword
in /etc/ssh/sshd_config:

# grep -i \"^PrintLastLog\" /etc/ssh/sshd_config

If the \"PrintLastLog\" keyword is not present, this is not a finding.  If the
value is not set to \"yes\", this is a finding."
  tag "fix": "Update the \"PrintLastLog\" keyword to \"yes\" in
/etc/ssh/sshd_config:

PrintLastLog yes

While it is acceptable to remove the keyword entirely since the default action
for the SSH daemon is to print the last logon date and time, it is preferred to
have the value explicitly documented."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

