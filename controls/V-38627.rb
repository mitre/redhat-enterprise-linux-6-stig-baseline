control "V-38627" do
  title "The openldap-servers package must not be installed unless required."
  desc  "Unnecessary packages should not be installed to decrease the attack
surface of the system."
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38627"
  tag "rid": "SV-50428r2_rule"
  tag "stig_id": "RHEL-06-000256"
  tag "fix_id": "F-43577r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "To verify the \"openldap-servers\" package is not installed,
run the following command:

$ rpm -q openldap-servers

The output should show the following.

package openldap-servers is not installed


If it does not, this is a finding."
  tag "fix": "The \"openldap-servers\" package should be removed if not in use.

# yum erase openldap-servers

The openldap-servers RPM is not installed by default on RHEL6 machines. It is
needed only by the OpenLDAP server, not by the clients which use LDAP for
authentication. If the system is not intended for use as an LDAP Server it
should be removed."

  describe package("openldap-servers") do
    it { should_not be_installed }
  end
end

