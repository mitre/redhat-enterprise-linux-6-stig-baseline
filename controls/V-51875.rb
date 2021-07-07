control "V-51875" do
  title "The operating system, upon successful logon/access, must display to
the user the number of unsuccessful logon/access attempts since the last
successful logon/access."
  desc  "Users need to be aware of activity that occurs regarding their
account. Providing users with information regarding the number of unsuccessful
attempts that were made to login to their account allows the user to determine
if any unauthorized activity has occurred and gives them an opportunity to
notify administrators. "
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-51875"
  tag "rid": "SV-66089r1_rule"
  tag "stig_id": "RHEL-06-000372"
  tag "fix_id": "F-56701r1_fix"
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
  desc 'check', "To ensure that last logon/access notification is configured
correctly, run the following command:

# grep pam_lastlog.so /etc/pam.d/system-auth

The output should show output \"showfailed\". If that is not the case, this is
a finding. "
  desc 'fix', "To configure the system to notify users of last logon/access
using \"pam_lastlog\", add the following line immediately after \"session
required pam_limits.so\":

session required pam_lastlog.so showfailed"

  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*session\s+(required|requisite)?\s+pam_lastlog.so[\s\w\d\=]+showfailed/) }
  end
end

