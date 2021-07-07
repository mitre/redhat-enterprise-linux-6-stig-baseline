control "V-38475" do
  title "The system must require passwords to contain a minimum of 15
characters."
  desc  "Requiring a minimum password length makes password cracking attacks
more difficult by ensuring a larger search space. However, any security benefit
from an onerous requirement must be carefully weighed against usability
problems, support costs, or counterproductive behavior that may result.

    While it does not negate the password length requirement, it is preferable
to migrate from a password-based authentication scheme to a stronger one based
on PKI (public key infrastructure).
  "
  impact 'medium'
  tag "gtitle": "SRG-OS-000078"
  tag "gid": "V-38475"
  tag "rid": "SV-50275r3_rule"
  tag "stig_id": "RHEL-06-000050"
  tag "fix_id": "F-43419r3_fix"
  tag "cci": ["CCI-000205"]
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
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
  desc 'check', "To check the minimum password length, run the command:

$ grep PASS_MIN_LEN /etc/login.defs

The DoD requirement is \"15\".

If it is not set to the required value, this is a finding.

$ grep –E 'pam_cracklib.so.*minlen' /etc/pam.d/*

If no results are returned, this is not a finding.

If any results are returned and are not set to \"15\" or greater, this is a
finding.
"
  desc 'fix', "To specify password length requirements for new accounts, edit
the file \"/etc/login.defs\" and add or correct the following lines:

PASS_MIN_LEN 15

The DoD requirement is \"15\". If a program consults \"/etc/login.defs\" and
also another PAM module (such as \"pam_cracklib\") during a password change
operation, then the most restrictive must be satisfied."

  describe file("/etc/login.defs") do
    its("content") { should match(/^PASS_MIN_LEN\s+(\d+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^PASS_MIN_LEN\s+(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 15 }
    end
  end
end

