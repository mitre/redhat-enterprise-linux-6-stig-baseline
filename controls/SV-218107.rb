# encoding: UTF-8

control "SV-218107" do
  title "The sudo command must require authentication."
  desc "The \"sudo\" command allows authorized users to run programs (including shells) as other users, system users, and root. The \"/etc/sudoers\" file is used to configure authorized \"sudo\" users as well as the programs they are allowed to run. Some configuration options in the \"/etc/sudoers\" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts."
  desc "default", "The \"sudo\" command allows authorized users to run programs
(including shells) as other users, system users, and root. The \"/etc/sudoers\"
file is used to configure authorized \"sudo\" users as well as the programs
they are allowed to run. Some configuration options in the \"/etc/sudoers\"
file allow configured users to run programs without re-authenticating. Use of
these configuration options makes it easier for one compromised account to be
used to compromise other accounts."
  desc "check", "Verify neither the \"NOPASSWD\" option nor the \"!authenticate\" option is configured for use in \"/etc/sudoers\" and associated files. Note that the \"#include\" and \"#includedir\" directives may be used to include configuration data from locations other than the defaults enumerated here.

# egrep '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*
# egrep '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/*

If any occurrences of \"NOPASSWD\" or “!authenticate” are returned from these commands and have not been documented with the Information System Security Officer (ISSO) as an organizationally defined administrative group utilizing MFA, this is a finding."
  desc "fix", "Update the \"/etc/sudoers\" or other sudo configuration files to remove or comment out lines utilizing the \"NOPASSWD\" and \"!authenticate\" options.

# visudo
# visudo -f [other sudo configuration file]"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000373"
  tag gid: "V-218107"
  tag rid: "SV-218107r603264_rule"
  tag stig_id: "RHEL-06-000529"
  tag fix_id: "F-36300r602610_fix"
  tag cci: ["CCI-002038"]
  tag nist: ["IA-11", "Rev_4"]

  describe command("grep -ie '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*") do
    its('stdout') { should be_empty }
  end
  describe command("grep -ie '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/*") do
    its('stdout') { should be_empty }
  end
end