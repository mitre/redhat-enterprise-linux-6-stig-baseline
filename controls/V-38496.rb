control "V-38496" do
  title "Default operating system accounts, other than root, must be locked."
  desc  "Disabling authentication for default system accounts makes it more
difficult for attackers to make use of them to compromise a system."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38496"
  tag "rid": "SV-50297r3_rule"
  tag "stig_id": "RHEL-06-000029"
  tag "fix_id": "F-43442r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "To obtain a listing of all users and the contents of their
shadow password field, run the command:

$ awk -F: '$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1 \":\" $2}' /etc/shadow

Identify the operating system accounts from this listing. These will primarily
be the accounts with UID numbers less than 500, other than root.

If any default operating system account (other than root) has a valid password
hash, this is a finding."
  tag "fix": "Some accounts are not associated with a human user of the system,
and exist to perform some administrative function. An attacker should not be
able to log into these accounts.

Disable logon access to these accounts with the command:

# passwd -l [SYSACCT]"

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

