# encoding: UTF-8

control "SV-218106" do
  title "The noexec option must be added to the /tmp partition."
  desc "Allowing users to execute binaries from world-writable directories such as \"/tmp\" should never be necessary in normal operation and can expose the system to potential compromise."
  desc "default", "Allowing users to execute binaries from world-writable directories
such as \"/tmp\" should never be necessary in normal operation and can expose
the system to potential compromise."
  desc "check", "To verify that binaries cannot be directly executed from the /tmp directory, run the following command:

$ grep '\\s/tmp' /etc/fstab

The resulting output will show whether the /tmp partition has the \"noexec\" flag set. If the /tmp partition does not have the noexec flag set, this is a finding."
  desc "fix", "The \"noexec\" mount option can be used to prevent binaries from being executed out of \"/tmp\". Add the \"noexec\" option to the fourth column of \"/etc/fstab\" for the line which controls mounting of \"/tmp\"."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000095"
  tag gid: "V-218106"
  tag rid: "SV-218106r603264_rule"
  tag stig_id: "RHEL-06-000528"
  tag fix_id: "F-19585r377334_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  # TODO should we check the /dev/shm directory also?
  if mount('/tmp').mounted?
    describe mount('/tmp') do
      its('options') { should include 'noexec' }
    end
  else
    describe "/tmp partition not found" do
      skip "/tmp partition not found, this control must be reviewed manually"
    end
  end
end