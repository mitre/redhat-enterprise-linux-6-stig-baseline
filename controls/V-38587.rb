control 'V-38587' do
  title 'The telnet-server package must not be installed.'
  desc  "Removing the \"telnet-server\" package decreases the risk of the
unencrypted telnet service's accidental (or intentional) activation.

    Mitigation:  If the telnet-server package is configured to only allow
encrypted sessions, such as with Kerberos or the use of encrypted network
tunnels, the risk of exposing sensitive information is mitigated.
  "
  impact 0.7
  tag "gtitle": 'SRG-OS-000095'
  tag "gid": 'V-38587'
  tag "rid": 'SV-50388r1_rule'
  tag "stig_id": 'RHEL-06-000206'
  tag "fix_id": 'F-43535r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
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
  tag "check": "Run the following command to determine if the \"telnet-server\"
package is installed:

# rpm -q telnet-server


If the package is installed, this is a finding."
  tag "fix": "The \"telnet-server\" package can be uninstalled with the
following command:

# yum erase telnet-server"

  describe package('telnet-server') do
    it { should_not be_installed }
  end
end
