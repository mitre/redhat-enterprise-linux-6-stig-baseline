# encoding: UTF-8

control "SV-218069" do
  title "The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system."
  desc "Using the \"-s\" option causes the TFTP service to only serve files from the given directory. Serving files from an intentionally specified directory reduces the risk of sharing files which should remain private."
  desc "default", "Using the \"-s\" option causes the TFTP service to only serve files
from the given directory. Serving files from an intentionally specified
directory reduces the risk of sharing files which should remain private."
  desc "check", "Verify the \"tftp\" package is installed:
# rpm -qa | grep -i tftp
tftp-5.2-22.e16.x86_64

If the \"tftp\" package is not installed, this is Not Applicable.

Verify \"tftp\" is configured by with the \"-s\" option by running the following command: 

grep \"server_args\" /etc/xinetd.d/tftp

The output should indicate the \"server_args\" variable is configured with the \"-s\" flag, matching the example below:

# grep \"server_args\" /etc/xinetd.d/tftp
server_args = -s /var/lib/tftpboot

If it does not, this is a finding."
  desc "fix", "If running the \"tftp\" service is necessary, it should be configured to change its root directory at startup. To do so, ensure \"/etc/xinetd.d/tftp\" includes \"-s\" as a command line argument, as shown in the following example (which is also the default): 

server_args = -s /var/lib/tftpboot"
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-218069"
  tag rid: "SV-218069r603264_rule"
  tag stig_id: "RHEL-06-000338"
  tag fix_id: "F-19548r377223_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe.one do
    describe package("tftp-server") do
      it { should_not be_installed }
    end
    describe file("/etc/xinetd.d/tftp") do
      its("content") { should match(/^[\s]*server_args[\s]+=[\s]+\-s[\s]+.+$/) }
    end
  end
end