# encoding: UTF-8

control "SV-217861" do
  title "The system must use a Linux Security Module configured to enforce limits on system services."
  desc "Setting the SELinux state to enforcing ensures SELinux is able to confine potentially compromised processes to the security policy, which is designed to prevent them from causing damage to the system or further elevating their privileges. 

Per OPORD 16-0080, the preferred intrusion detection system is McAfee Host Intrusion Prevention System (HIPS) in conjunction with SELinux. However, McAfee Endpoint Security for Linux (ENSL) is an approved alternative to both McAfee Virus Scan Enterprise (VSE) and HIPS. In either scenario, SELinux is interoperable with the McAfee products and SELinux is still required."
  desc "default", "Setting the SELinux state to enforcing ensures SELinux is able to
confine potentially compromised processes to the security policy, which is
designed to prevent them from causing damage to the system or further elevating
their privileges."
  desc "check", "If an HBSS or HIPS is active on the system, this is Not Applicable.

Check the file \"/etc/selinux/config\" and ensure the following line appears:

SELINUX=enforcing

If SELINUX is not set to enforcing, this is a finding."
  desc "fix", "The SELinux state should be set to \"enforcing\" at system boot time. In the file \"/etc/selinux/config\", add or correct the following line to configure the system to boot into enforcing mode:

SELINUX=enforcing"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000324"
  tag gid: "V-217861"
  tag rid: "SV-217861r603264_rule"
  tag stig_id: "RHEL-06-000020"
  tag fix_id: "F-19340r462505_fix"
  tag cci: ["CCI-000366", "CCI-002165", "CCI-002235"]
  tag nist: ["CM-6 b", "Rev_4", "AC-3 (4)", "AC-6 (10)"]

  describe file("/etc/selinux/config") do
    its("content") { should match(/^[\s]*SELINUX[\s]*=[\s]*(.*)[\s]*$/) }
  end
  file("/etc/selinux/config").content.to_s.scan(/^[\s]*SELINUX[\s]*=[\s]*(.*)[\s]*$/).flatten.each do |entry|
    describe entry do
      it { should eq "enforcing" }
    end
  end
end