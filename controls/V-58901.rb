control "V-58901" do
  title "The sudo command must require authentication."
  desc  "The \"sudo\" command allows authorized users to run programs
(including shells) as other users, system users, and root. The \"/etc/sudoers\"
file is used to configure authorized \"sudo\" users as well as the programs
they are allowed to run. Some configuration options in the \"/etc/sudoers\"
file allow configured users to run programs without re-authenticating. Use of
these configuration options makes it easier for one compromised account to be
used to compromise other accounts."
  impact 'medium'
  tag "gtitle": "SRG-OS-000373"
  tag "gid": "V-58901"
  tag "rid": "SV-73331r2_rule"
  tag "stig_id": "RHEL-06-000529"
  tag "fix_id": "F-64285r1_fix"
  tag "cci": ["CCI-002038"]
  tag "nist": ["IA-11", "Rev_4"]
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
  desc 'check', "If passwords are not being used for authentication, this is Not
Applicable.

Verify neither the \"NOPASSWD\" option nor the \"!authenticate\" option is
configured for use in \"/etc/sudoers\" and associated files. Note that the
\"#include\" and \"#includedir\" directives may be used to include
configuration data from locations other than the defaults enumerated here.

# egrep '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*
# egrep '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/*

If the \"NOPASSWD\" or \"!authenticate\" options are configured for use in
\"/etc/sudoers\" or associated files, this is a finding."
  desc 'fix', "Update the \"/etc/sudoers\" or other sudo configuration files to
remove or comment out lines utilizing the \"NOPASSWD\" and \"!authenticate\"
options.

# visudo
# visudo -f [other sudo configuration file]"

  describe command("grep -ie '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*") do
    its('stdout') { should be_empty }
  end

  describe command("grep -ie '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/*") do
    its('stdout') { should be_empty }
  end
end

