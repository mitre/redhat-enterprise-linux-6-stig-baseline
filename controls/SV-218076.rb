# encoding: UTF-8

control "SV-218076" do
  title "The system default umask in /etc/login.defs must be 077."
  desc "The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users."
  desc "default", "The umask value influences the permissions assigned to files when they
are created. A misconfigured umask value could result in files with excessive
permissions that can be read and/or written to by unauthorized users."
  desc "check", "Verify the \"umask\" setting is configured correctly in the \"/etc/login.defs\" file by running the following command: 

# grep -i \"umask\" /etc/login.defs

All output must show the value of \"umask\" set to 077, as shown in the below: 

# grep -i \"umask\" /etc/login.defs
UMASK 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding."
  desc "fix", "To ensure the default umask controlled by \"/etc/login.defs\" is set properly, add or correct the \"umask\" setting in \"/etc/login.defs\" to read as follows: 

UMASK 077"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218076"
  tag rid: "SV-218076r603264_rule"
  tag stig_id: "RHEL-06-000345"
  tag fix_id: "F-19555r377244_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/login.defs") do
    its("content") { should match(/^[\s]*UMASK[\s]+([^#\s]*)/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^[\s]*UMASK[\s]+([^#\s]*)/).flatten.each do |entry|
    describe entry do
      it { should eq "077" }
    end
  end
end