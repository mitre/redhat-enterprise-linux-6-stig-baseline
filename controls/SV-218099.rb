# encoding: UTF-8

control "SV-218099" do
  title "The system package management tool must verify contents of all files associated with packages."
  desc "The hash on important files like system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system."
  desc "default", "The hash on important files like system executables should match the
information given by the RPM database. Executables with erroneous hashes could
be a sign of nefarious activity on the system."
  desc "check", "The following command will list which files on the system have file hashes different from what is expected by the RPM database: 

# rpm -Va | awk '$1 ~ /..5/ && $2 != \"c\"'

If there is any output from the command for system binaries, verify that the changes were due to STIG application and have been documented with the ISSO.

If there are changes to system binaries and they are not documented with the ISSO, this is a finding."
  desc "fix", "The RPM package management system can check the hashes of installed software packages, including many that are important to system security. Run the following command to list which files on the system have hashes that differ from what is expected by the RPM database: 

# rpm -Va | awk '$1 ~ /..5/ && $2 != \"c\"'

If the file that has changed was not expected to, refresh from distribution media or online repositories. 

rpm -Uvh [affected_package]

OR 

yum reinstall [affected_package]"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218099"
  tag rid: "SV-218099r603264_rule"
  tag stig_id: "RHEL-06-000519"
  tag fix_id: "F-19578r377313_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  # TODO check against an exception list attribute
  describe command("rpm -Va | awk '$1 ~ /..5/ && $2 != \"c\"'") do
    its('stdout.strip') { should be_empty }
  end
end