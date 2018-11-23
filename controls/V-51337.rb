control "V-51337" do
  title "The system must use a Linux Security Module at boot time."
  desc  "Disabling a major host protection feature, such as SELinux, at boot
time prevents it from confining system services at boot time. Further, it
increases the chances that it will remain off during system operation."
  impact 'medium'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-51337"
  tag "rid": "SV-65547r2_rule"
  tag "stig_id": "RHEL-06-000017"
  tag "fix_id": "F-56147r2_fix"
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
  desc 'check', "Inspect \"/boot/grub/grub.conf\" for any instances of
\"selinux=0\" in the kernel boot arguments. Presence of \"selinux=0\" indicates
that SELinux is disabled at boot time. If SELinux is disabled at boot time,
this is a finding."
  desc 'fix', "SELinux can be disabled at boot time by an argument in
\"/boot/grub/grub.conf\". Remove any instances of \"selinux=0\" from the kernel
arguments in that file to prevent SELinux from being disabled at boot. "

  describe file("/boot/grub/grub.conf") do
    its("content") { should_not match(/^[\s]*kernel[\s]+.*(selinux|enforcing)=0.*$/) }
  end
end

