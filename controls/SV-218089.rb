# encoding: UTF-8

control "SV-218089" do
  title "The operating system must conduct backups of system-level information contained in the information system per organization defined frequency to conduct backups that are consistent with recovery time and recovery point objectives."
  desc "Operating system backup is a critical step in maintaining data assurance and availability. System-level information includes system-state information, operating system and application software, and licenses. Backups must be consistent with organizational recovery time and recovery point objectives."
  desc "default", "Operating system backup is a critical step in maintaining data
assurance and availability. System-level information includes system-state
information, operating system and application software, and licenses. Backups
must be consistent with organizational recovery time and recovery point
objectives."
  desc "check", "Ask an administrator if a process exists to back up OS data from the system, including configuration data. 

If such a process does not exist, this is a finding."
  desc "fix", "Procedures to back up OS data from the system must be established and executed. The Red Hat operating system provides utilities for automating such a process.  Commercial and open-source products are also available.

Implement a process whereby OS data is backed up from the system in accordance with local policies."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218089"
  tag rid: "SV-218089r603264_rule"
  tag stig_id: "RHEL-06-000505"
  tag fix_id: "F-19568r377283_fix"
  tag cci: ["CCI-000537", "CCI-000366"]
  tag nist: ["CP-9b", "Rev_4", "CM-6 b"]

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end