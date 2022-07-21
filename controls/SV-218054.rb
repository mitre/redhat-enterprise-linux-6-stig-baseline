# encoding: UTF-8

control "SV-218054" do
  title "Process core dumps must be disabled unless needed."
  desc "A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems."
  desc "default", "A core dump includes a memory image taken at the time the operating
system terminates an application. The memory image could contain sensitive data
and is generally useful only for developers trying to debug problems."
  desc "check", "To verify that core dumps are disabled for all users, run the following command:

$ grep core /etc/security/limits.conf /etc/security/limits.d/*.conf

The output should be:

* hard core 0

If it is not, this is a finding."
  desc "fix", "To disable core dumps for all users, add the following line to \"/etc/security/limits.conf\": 

* hard core 0"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218054"
  tag rid: "SV-218054r603264_rule"
  tag stig_id: "RHEL-06-000308"
  tag fix_id: "F-19533r377178_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe limits_conf do
    its('*') { should include ['hard', 'core', '0'] }
  end
end