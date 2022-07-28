# encoding: UTF-8

control "SV-217846" do
  title "The system must use a separate file system for /tmp."
  desc "The \"/tmp\" partition is used as temporary storage by many programs. Placing \"/tmp\" in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it."
  desc "default", "The \"/tmp\" partition is used as temporary storage by many programs.
Placing \"/tmp\" in its own partition enables the setting of more restrictive
mount options, which can help protect programs which use it."
  desc "check", "Run the following command to determine if \"/tmp\" is on its own partition or logical volume: 

$ mount | grep \"on /tmp \"

If \"/tmp\" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding."
  desc "fix", "The \"/tmp\" directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217846"
  tag rid: "SV-217846r603264_rule"
  tag stig_id: "RHEL-06-000001"
  tag fix_id: "F-19325r376554_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe mount("/tmp") do
    it { should be_mounted }
  end
end