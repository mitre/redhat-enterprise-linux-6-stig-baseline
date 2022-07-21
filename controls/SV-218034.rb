# encoding: UTF-8

control "SV-218034" do
  title "There must be no world-writable files on the system."
  desc "Data in world-writable files can be modified by any user on the system. In almost all circumstances, files can be configured using a combination of user and group permissions to support whatever legitimate access is needed without the risk caused by world-writable files."
  desc "default", "Data in world-writable files can be modified by any user on the
system. In almost all circumstances, files can be configured using a
combination of user and group permissions to support whatever legitimate access
is needed without the risk caused by world-writable files."
  desc "check", "To find world-writable files, run the following command for each local partition [PART], excluding special filesystems such as /selinux, /proc, or /sys: 

# find [PART] -xdev -type f -perm -002

If there is output, this is a finding."
  desc "fix", "It is generally a good idea to remove global (other) write access to a file when it is discovered. However, check with documentation for specific applications before making changes. Also, monitor for recurring world-writable files, as these may be symptoms of a misconfigured application or user account."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218034"
  tag rid: "SV-218034r603264_rule"
  tag stig_id: "RHEL-06-000282"
  tag fix_id: "F-19513r377118_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  files = command(%(find / -xautofs -noleaf -wholename '/proc' -prune -o -wholename '/sys' -prune -o -wholename '/dev' -prune -o -wholename '/selinux' -prune -o -type f -perm -002 -print))
  describe "World-writable files" do
    subject { files.stdout.strip.split("\n") }
    it { should be_empty }
  end
end