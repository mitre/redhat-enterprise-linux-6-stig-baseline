control 'V-38621' do
  title "The system clock must be synchronized to an authoritative DoD time
source."
  desc  "Synchronizing with an NTP server makes it possible to collate system
logs from multiple sources or correlate computer events with real time events.
Using a trusted NTP server provided by your organization is recommended."
  impact 0.5
  tag "gtitle": 'SRG-OS-000056'
  tag "gid": 'V-38621'
  tag "rid": 'SV-50422r1_rule'
  tag "stig_id": 'RHEL-06-000248'
  tag "fix_id": 'F-43570r1_fix'
  tag "cci": ['CCI-000160']
  tag "nist": ['AU-8 (1)', 'Rev_4']
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
  tag "check": "A remote NTP server should be configured for time
synchronization. To verify one is configured, open the following file.

/etc/ntp.conf

In the file, there should be a section similar to the following:

# --- OUR TIMESERVERS -----
server [ntpserver]


If this is not the case, this is a finding."
  tag "fix": "To specify a remote NTP server for time synchronization, edit the
file \"/etc/ntp.conf\". Add or correct the following lines, substituting the IP
or hostname of a remote NTP server for ntpserver.

server [ntpserver]

This instructs the NTP software to contact that remote server to obtain time
data."

  describe file('/etc/ntp.conf') do
    its('content') { should match(/^[\s]*server[\s]+.+$/) }
  end
end
