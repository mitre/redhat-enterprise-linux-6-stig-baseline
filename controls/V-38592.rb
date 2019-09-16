control "V-38592" do
  title "The system must require administrator action to unlock an account
locked by excessive failed login attempts."
  desc  "Locking out user accounts after a number of incorrect attempts
prevents direct password guessing attacks. Ensuring that an administrator is
involved in unlocking locked accounts draws appropriate attention to such
situations."
  impact 0.5
  tag "gtitle": "SRG-OS-000022"
  tag "gid": "V-38592"
  tag "rid": "SV-50393r4_rule"
  tag "stig_id": "RHEL-06-000356"
  tag "fix_id": "F-43541r6_fix"
  tag "cci": ["CCI-000047"]
  tag "nist": ["AC-7 b", "Rev_4"]
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
  tag "check": "To ensure the failed password attempt policy is configured
correctly, run the following command:

# grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

The output should show \"unlock_time=<some-large-number>\"; the largest
acceptable value is 604800 seconds (one week).
If that is not the case, this is a finding."
  tag "fix": "To configure the system to lock out accounts after a number of
incorrect logon attempts and require an administrator to unlock the account
using \"pam_faillock.so\", modify the content of both
\"/etc/pam.d/system-auth\" and \"/etc/pam.d/password-auth\" as follows:

Add the following line immediately before the \"pam_unix.so\" statement in the
\"AUTH\" section:

auth required pam_faillock.so preauth silent deny=3 unlock_time=604800
fail_interval=900

Add the following line immediately after the \"pam_unix.so\" statement in the
\"AUTH\" section:

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800
fail_interval=900

Add the following line immediately before the \"pam_unix.so\" statement in the
\"ACCOUNT\" section:

account required pam_faillock.so

Note that any updates made to \"/etc/pam.d/system-auth\" and
\"/etc/pam.d/password-auth\" may be overwritten by the \"authconfig\" program.
The \"authconfig\" program should not be used."

  file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*auth\s+(?:(?:sufficient)|(?:\[default=die\]))\s+pam_faillock\.so\s+authfail.*\s+unlock_time=([0-9]+).*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= input('pam_faillock_unlock_time') }
    end
  end
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*auth\s+(?:(?:sufficient)|(?:\[default=die\]))\s+pam_faillock\.so\s+authfail.*\s+unlock_time=([0-9]+).*$/) }
  end
  file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*auth\s+(?:(?:sufficient)|(?:\[default=die\]))\s+pam_faillock\.so\s+authfail.*\s+unlock_time=([0-9]+).*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= input('pam_faillock_unlock_time') }
    end
  end
  describe file("/etc/pam.d/password-auth") do
    its("content") { should match(/^\s*auth\s+(?:(?:sufficient)|(?:\[default=die\]))\s+pam_faillock\.so\s+authfail.*\s+unlock_time=([0-9]+).*$/) }
  end
end

