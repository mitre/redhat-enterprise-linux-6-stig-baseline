# encoding: UTF-8

control "SV-217987" do
  title "The rexecd service must not be running."
  desc "The rexec service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network."
  desc "default", "The rexec service uses unencrypted network communications, which means
that data from the login session, including passwords and all other information
transmitted during the session, can be stolen by eavesdroppers on the network."
  desc "check", "To check that the \"rexec\" service is disabled in system boot configuration, run the following command:

# chkconfig \"rexec\" --list

Output should indicate the \"rexec\" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig \"rexec\" --list
rexec off
OR
error reading information on service rexec: No such file or directory


If the service is running, this is a finding."
  desc "fix", "The \"rexec\" service, which is available with the \"rsh-server\" package and runs as a service through xinetd, should be disabled. The \"rexec\" service can be disabled with the following command: 

# chkconfig rexec off"
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000033"
  tag gid: "V-217987"
  tag rid: "SV-217987r603264_rule"
  tag stig_id: "RHEL-06-000216"
  tag fix_id: "F-19466r376977_fix"
  tag cci: ["CCI-000068"]
  tag nist: ["AC-17 (2)", "Rev_4"]

  describe.one do
    describe package("rsh-server") do
      it { should_not be_installed }
    end
    describe file("/etc/xinetd.d/rexec") do
      its("content") { should match(/^\s*disable\s+=\s+yes\s*$/) }
    end
  end
end