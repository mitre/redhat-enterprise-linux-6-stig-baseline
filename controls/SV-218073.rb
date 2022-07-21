# encoding: UTF-8

control "SV-218073" do
  title "The system default umask for the bash shell must be 077."
  desc "The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users."
  desc "default", "The umask value influences the permissions assigned to files when they
are created. A misconfigured umask value could result in files with excessive
permissions that can be read and/or written to by unauthorized users."
  desc "check", "Verify the \"umask\" setting is configured correctly in the \"/etc/bashrc\" file by running the following command: 

# grep \"umask\" /etc/bashrc

All output must show the value of \"umask\" set to 077, as shown below: 

# grep \"umask\" /etc/bashrc
umask 077
umask 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding."
  desc "fix", "To ensure the default umask for users of the Bash shell is set properly, add or correct the \"umask\" setting in \"/etc/bashrc\" to read as follows: 

umask 077"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218073"
  tag rid: "SV-218073r603264_rule"
  tag stig_id: "RHEL-06-000342"
  tag fix_id: "F-19552r377235_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe file("/etc/bashrc") do
    its("content") { should match(/^[\s]*umask[\s]+([^#\s]*)/) }
  end
  file("/etc/bashrc").content.to_s.scan(/^[\s]*umask[\s]+([^#\s]*)/).flatten.each do |entry|
    describe entry do
      it { should eq "077" }
    end
  end
end