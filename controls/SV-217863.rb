# encoding: UTF-8

control "SV-217863" do
  title "The system must use a Linux Security Module configured to limit the privileges of system services."
  desc "Setting the SELinux policy to \"targeted\" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services."
  desc "default", "Setting the SELinux policy to \"targeted\" or a more specialized
policy ensures the system will confine processes that are likely to be targeted
for exploitation, such as network or system services."
  desc "check", "Check the file \"/etc/selinux/config\" and ensure the following line appears:

SELINUXTYPE=targeted

If it does not, this is a finding."
  desc "fix", "The SELinux \"targeted\" policy is appropriate for general-purpose desktops and servers, as well as systems in many other roles. To configure the system to use this policy, add or correct the following line in \"/etc/selinux/config\":

SELINUXTYPE=targeted

Other policies, such as \"mls\", provide additional security labeling and greater confinement but are not compatible with many general-purpose use cases."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000324"
  tag gid: "V-217863"
  tag rid: "SV-217863r603264_rule"
  tag stig_id: "RHEL-06-000023"
  tag fix_id: "F-19342r376605_fix"
  tag cci: ["CCI-000366", "CCI-002235", "CCI-002165"]
  tag nist: ["CM-6 b", "Rev_4", "AC-6 (10)", "AC-3 (4)"]

  describe file("/etc/selinux/config") do
    its("content") { should match(/^[\s]*SELINUXTYPE[\s]*=[\s]*([^\s]*)/) }
  end
  file("/etc/selinux/config").content.to_s.scan(/^[\s]*SELINUXTYPE[\s]*=[\s]*([^\s]*)/).flatten.each do |entry|
    describe entry do
      it { should eq "targeted" }
    end
  end
end