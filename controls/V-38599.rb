control 'V-38599' do
  title "The FTPS/FTP service on the system must be configured with the
Department of Defense (DoD) login banner."
  desc  "This setting will cause the system greeting banner to be used for FTP
connections as well."
  impact 0.5
  tag "gtitle": 'SRG-OS-000023'
  tag "gid": 'V-38599'
  tag "rid": 'SV-50400r2_rule'
  tag "stig_id": 'RHEL-06-000348'
  tag "fix_id": 'F-43564r3_fix'
  tag "cci": ['CCI-000048']
  tag "nist": ['AC-8 a', 'Rev_4']
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
  tag "check": "To verify this configuration, run the following command:

grep \"banner_file\" /etc/vsftpd/vsftpd.conf

The output should show the value of \"banner_file\" is set to \"/etc/issue\",
an example of which is shown below.

# grep \"banner_file\" /etc/vsftpd/vsftpd.conf
banner_file=/etc/issue


If it does not, this is a finding."
  tag "fix": "Edit the vsftpd configuration file, which resides at
\"/etc/vsftpd/vsftpd.conf\" by default. Add or correct the following
configuration options.

banner_file=/etc/issue

Restart the vsftpd daemon.

# service vsftpd restart"

  if package('vsftpd').installed?
    describe file('/etc/vsftpd/vsftpd.conf') do
      it { should exist }
    end
    describe parse_config_file('/etc/vsftpd/vsftpd.conf') do
      its('banner_file') { should eq '/etc/issue' }
    end
  else
    impact 0.0
    describe 'Package vsftpd not installed' do
      skip 'Package vsftpd not installed, this control Not Applicable'
    end
  end
end
