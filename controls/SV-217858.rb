# encoding: UTF-8

control "SV-217858" do
  title "The system must use a Linux Security Module at boot time."
  desc "Disabling a major host protection feature, such as SELinux, at boot time prevents it from confining system services at boot time. Further, it increases the chances that it will remain off during system operation."
  desc "default", "Disabling a major host protection feature, such as SELinux, at boot
time prevents it from confining system services at boot time. Further, it
increases the chances that it will remain off during system operation."
  desc "check", "Inspect \"/boot/grub/grub.conf\" for any instances of \"selinux=0\" in the kernel boot arguments. Presence of \"selinux=0\" indicates that SELinux is disabled at boot time. If SELinux is disabled at boot time, this is a finding."
  desc "fix", "SELinux can be disabled at boot time by an argument in \"/boot/grub/grub.conf\". Remove any instances of \"selinux=0\" from the kernel arguments in that file to prevent SELinux from being disabled at boot."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000445"
  tag gid: "V-217858"
  tag rid: "SV-217858r603264_rule"
  tag stig_id: "RHEL-06-000017"
  tag fix_id: "F-19337r376590_fix"
  tag cci: ["CCI-000366", "CCI-002163", "CCI-002696"]
  tag nist: ["CM-6 b", "Rev_4", "AC-3 (4)", "SI-6 a"]

  describe file("/boot/grub/grub.conf") do
    its("content") { should_not match(/^[\s]*kernel[\s]+.*(selinux|enforcing)=0.*$/) }
  end
end