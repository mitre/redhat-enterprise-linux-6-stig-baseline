# encoding: UTF-8

control "SV-218074" do
  title "The system default umask for the csh shell must be 077."
  desc "The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users."
  desc "default", "The umask value influences the permissions assigned to files when they
are created. A misconfigured umask value could result in files with excessive
permissions that can be read and/or written to by unauthorized users."
  desc "check", "Verify the \"umask\" setting is configured correctly in the \"/etc/csh.cshrc\" file by running the following command: 

# grep \"umask\" /etc/csh.cshrc

All output must show the value of \"umask\" set to 077, as shown in the below: 

# grep \"umask\" /etc/csh.cshrc
umask 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding."
  desc "fix", "To ensure the default umask for users of the C shell is set properly, add or correct the \"umask\" setting in \"/etc/csh.cshrc\" to read as follows: 

umask 077"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218074"
  tag rid: "SV-218074r603264_rule"
  tag stig_id: "RHEL-06-000343"
  tag fix_id: "F-19553r377238_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe.one do
    describe file("/etc/csh.cshrc") do
      its("content") { should match(/^[\s]*umask[\s]+([^#\s]*)/) }
    end
    file("/etc/csh.cshrc").content.to_s.scan(/^[\s]*umask[\s]+([^#\s]*)/).flatten.each do |entry|
      describe entry do
        it { should eq "077" }
      end
    end
    describe package("tcsh") do
      it { should_not be_installed }
    end
    describe file("/etc/csh.cshrc") do
      it { should_not exist }
    end
  end
end