control "V-38702" do
  title "The FTP daemon must be configured for logging or verbose mode."
  desc  "To trace malicious activity facilitated by the FTP service, it must be
configured to ensure that all commands sent to the ftp server are logged using
the verbose vsftpd log format. The default vsftpd log file is
/var/log/vsftpd.log."
  impact 'low'
  tag "gtitle": "SRG-OS-000037"
  tag "gid": "V-38702"
  tag "rid": "SV-50503r1_rule"
  tag "stig_id": "RHEL-06-000339"
  tag "fix_id": "F-43651r1_fix"
  tag "cci": ["CCI-000130"]
  tag "nist": ["AU-3", "Rev_4"]
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
  desc 'check', "Find if logging is applied to the ftp daemon.

Procedures:

If vsftpd is started by xinetd the following command will indicate the xinetd.d
startup file.

# grep vsftpd /etc/xinetd.d/*



# grep server_args [vsftpd xinetd.d startup file]

This will indicate the vsftpd config file used when starting through xinetd. If
the [server_args]line is missing or does not include the vsftpd configuration
file, then the default config file (/etc/vsftpd/vsftpd.conf) is used.

# grep xferlog_enable [vsftpd config file]


If xferlog_enable is missing, or is not set to yes, this is a finding."
  desc 'fix', "Add or correct the following configuration options within the
\"vsftpd\" configuration file, located at \"/etc/vsftpd/vsftpd.conf\".

xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES"

  describe parse_config_file('/etc/vsftpd/vsftpd.conf') do
    its('xferlog_enable') { should eq 'YES' }
  end
end

