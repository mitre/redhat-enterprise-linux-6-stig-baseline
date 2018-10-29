control "V-38446" do
  title "The mail system must forward all mail for root to one or more system
administrators."
  desc  "A number of system services utilize email messages sent to the root
user to notify system administrators of active or impending issues.  These
messages must be forwarded to at least one monitored email address."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38446"
  tag "rid": "SV-50246r2_rule"
  tag "stig_id": "RHEL-06-000521"
  tag "fix_id": "F-43391r1_fix"
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
  tag "check": "Find the list of alias maps used by the Postfix mail server:

# postconf alias_maps

Query the Postfix alias maps for an alias for \"root\":

# postmap -q root hash:/etc/aliases

If there are no aliases configured for root that forward to a monitored email
address, this is a finding."
  tag "fix": "Set up an alias for root that forwards to a monitored email
address:

# echo \"root: <system.administrator>@mail.mil\" >> /etc/aliases
# newaliases"

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

