# encoding: UTF-8

control "SV-217864" do
  title "All device files must be monitored by the system Linux Security Module."
  desc "If a device file carries the SELinux type \"unlabeled_t\", then SELinux cannot properly restrict access to the device file."
  desc "default", "If a device file carries the SELinux type \"unlabeled_t\", then
SELinux cannot properly restrict access to the device file."
  desc "check", "To check for unlabeled device files, run the following command:

# ls -RZ /dev | grep unlabeled_t

It should produce no output in a well-configured system. 

If there is output, this is a finding."
  desc "fix", "Device files, which are used for communication with important system resources, should be labeled with proper SELinux types. If any device files carry the SELinux type \"unlabeled_t\", investigate the cause and correct the file's context."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000324"
  tag gid: "V-217864"
  tag rid: "SV-217864r603264_rule"
  tag stig_id: "RHEL-06-000025"
  tag fix_id: "F-19343r376608_fix"
  tag cci: ["CCI-000366", "CCI-002165", "CCI-002235"]
  tag nist: ["CM-6 b", "Rev_4", "AC-3 (4)", "AC-6 (10)"]

  describe command("ls -RZ /dev | grep unlabeled_t") do
    its('stdout.strip') { should be_empty }
  end
end