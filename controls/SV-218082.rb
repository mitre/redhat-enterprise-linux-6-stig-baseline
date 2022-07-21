# encoding: UTF-8

control "SV-218082" do
  title "The system must disable accounts after excessive login failures within a 15-minute interval."
  desc "Locking out user accounts after a number of incorrect attempts within a specific period of time prevents direct password guessing attacks."
  desc "default", "Locking out user accounts after a number of incorrect attempts within
a specific period of time prevents direct password guessing attacks."
  desc "check", "To ensure the failed password attempt policy is configured correctly, run the following command:

$ grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

For each file, the output should show \"fail_interval=<interval-in-seconds>\" where \"interval-in-seconds\" is 900 (15 minutes) or greater. If the \"fail_interval\" parameter is not set, the default setting of 900 seconds is acceptable. If that is not the case, this is a finding."
  desc "fix", "Utilizing \"pam_faillock.so\", the \"fail_interval\" directive configures the system to lock out accounts after a number of incorrect logon attempts. Modify the content of both \"/etc/pam.d/system-auth\" and \"/etc/pam.d/password-auth\" as follows: 

Add the following line immediately before the \"pam_unix.so\" statement in the \"AUTH\" section: 

auth required pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900

Add the following line immediately after the \"pam_unix.so\" statement in the \"AUTH\" section: 

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900

Add the following line immediately before the \"pam_unix.so\" statement in the \"ACCOUNT\" section: 

account required pam_faillock.so

Note that any updates made to \"/etc/pam.d/system-auth\" and \"/etc/pam.d/password-auth\" may be overwritten by the \"authconfig\" program.  The \"authconfig\" program should not be used."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000329"
  tag gid: "V-218082"
  tag rid: "SV-218082r603264_rule"
  tag stig_id: "RHEL-06-000357"
  tag fix_id: "F-36299r602607_fix"
  tag cci: ["CCI-001452", "CCI-002238"]
  tag nist: ["AC-7 a", "Rev_4", "AC-7 b"]

  file("/etc/pam.d/system-auth").content.to_s.scan(/^\s*auth\s+(?:(?:sufficient)|(?:\[default=die\]))\s+pam_faillock\.so\s+authfail.*deny=(?:[0-9]+).*unlock_time=(?:[0-9]+).*fail_interval=([0-9]+).*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= input('pam_faillock_fail_interval') }
    end
  end
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*auth\s+(?:(?:sufficient)|(?:\[default=die\]))\s+pam_faillock\.so\s+authfail.*deny=(?:[0-9]+).*unlock_time=(?:[0-9]+).*fail_interval=([0-9]+).*$/) }
  end
  file("/etc/pam.d/password-auth").content.to_s.scan(/^\s*auth\s+(?:(?:sufficient)|(?:\[default=die\]))\s+pam_faillock\.so\s+authfail.*deny=(?:[0-9]+).*unlock_time=(?:[0-9]+).*fail_interval=([0-9]+).*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= input('pam_faillock_fail_interval') }
    end
  end
  describe file("/etc/pam.d/password-auth") do
    its("content") { should match(/^\s*auth\s+(?:(?:sufficient)|(?:\[default=die\]))\s+pam_faillock\.so\s+authfail.*deny=(?:[0-9]+).*unlock_time=(?:[0-9]+).*fail_interval=([0-9]+).*$/) }
  end
end