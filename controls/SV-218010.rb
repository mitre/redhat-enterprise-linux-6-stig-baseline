# encoding: UTF-8

control "SV-218010" do
  title "The openldap-servers package must not be installed unless required."
  desc "Unnecessary packages should not be installed to decrease the attack surface of the system."
  desc "default", "Unnecessary packages should not be installed to decrease the attack
surface of the system."
  desc "check", "To verify the \"openldap-servers\" package is not installed, run the following command: 

$ rpm -q openldap-servers

The output should show the following. 

package openldap-servers is not installed


If it does not, this is a finding."
  desc "fix", "The \"openldap-servers\" package should be removed if not in use.

# yum erase openldap-servers

The openldap-servers RPM is not installed by default on RHEL6 machines. It is needed only by the OpenLDAP server, not by the clients which use LDAP for authentication. If the system is not intended for use as an LDAP Server it should be removed."
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000095"
  tag gid: "V-218010"
  tag rid: "SV-218010r603264_rule"
  tag stig_id: "RHEL-06-000256"
  tag fix_id: "F-19489r377046_fix"
  tag cci: ["CCI-000366", "CCI-000381"]
  tag nist: ["CM-6 b", "Rev_4", "CM-7 a"]

  describe package("openldap-servers") do
    it { should_not be_installed }
  end
end