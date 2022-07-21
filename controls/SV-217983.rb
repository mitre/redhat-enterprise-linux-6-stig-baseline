# encoding: UTF-8

control "SV-217983" do
  title "The telnet-server package must not be installed."
  desc "Removing the \"telnet-server\" package decreases the risk of the unencrypted telnet service's accidental (or intentional) activation.

Mitigation:  If the telnet-server package is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated."
  desc "default", "Removing the \"telnet-server\" package decreases the risk of the
unencrypted telnet service's accidental (or intentional) activation.

    Mitigation:  If the telnet-server package is configured to only allow
encrypted sessions, such as with Kerberos or the use of encrypted network
tunnels, the risk of exposing sensitive information is mitigated."
  desc "check", "Run the following command to determine if the \"telnet-server\" package is installed: 

# rpm -q telnet-server


If the package is installed, this is a finding."
  desc "fix", "The \"telnet-server\" package can be uninstalled with the following command: 

# yum erase telnet-server"
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000095"
  tag gid: "V-217983"
  tag rid: "SV-217983r603264_rule"
  tag stig_id: "RHEL-06-000206"
  tag fix_id: "F-19462r376965_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]

  describe package("telnet-server") do
    it { should_not be_installed }
  end
end