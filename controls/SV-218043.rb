# encoding: UTF-8

control "SV-218043" do
  title "All GIDs referenced in /etc/passwd must be defined in /etc/group"
  desc "Inconsistency in GIDs between /etc/passwd and /etc/group could lead to a user having unintended rights."
  desc "default", "Inconsistency in GIDs between /etc/passwd and /etc/group could lead to
a user having unintended rights."
  desc "check", "To ensure all GIDs referenced in /etc/passwd are defined in /etc/group, run the following command: 

# pwck -r | grep 'no group'

There should be no output. 
If there is output, this is a finding."
  desc "fix", "Add a group to the system for each GID referenced without a corresponding group."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000104"
  tag gid: "V-218043"
  tag rid: "SV-218043r603264_rule"
  tag stig_id: "RHEL-06-000294"
  tag fix_id: "F-19522r377145_fix"
  tag cci: ["CCI-000366", "CCI-000764"]
  tag nist: ["CM-6 b", "Rev_4", "IA-2"]

  describe command("pwck -r | grep 'no group'") do
    its('stdout.strip') { should be_empty }
  end
end