control 'V-38520' do
  title "The operating system must back up audit records on an organization
defined frequency onto a different system or media than the system being
audited."
  desc  "A log server (loghost) receives syslog messages from one or more
systems. This data can be used as an additional log source in the event a
system is compromised and its local logs are suspect. Forwarding log messages
to a remote loghost also provides system administrators with a centralized
place to view the status of multiple hosts within the enterprise."
  impact 0.5
  tag "gtitle": 'SRG-OS-000215'
  tag "gid": 'V-38520'
  tag "rid": 'SV-50321r1_rule'
  tag "stig_id": 'RHEL-06-000136'
  tag "fix_id": 'F-43468r1_fix'
  tag "cci": ['CCI-001348']
  tag "nist": ['AU-9 (2)', 'Rev_4']
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
  tag "check": "To ensure logs are sent to a remote host, examine the file
\"/etc/rsyslog.conf\". If using UDP, a line similar to the following should be
present:

*.* @[loghost.example.com]

If using TCP, a line similar to the following should be present:

*.* @@[loghost.example.com]

If using RELP, a line similar to the following should be present:

*.* :omrelp:[loghost.example.com]


If none of these are present, this is a finding."
  tag "fix": "To configure rsyslog to send logs to a remote log server, open
\"/etc/rsyslog.conf\" and read and understand the last section of the file,
which describes the multiple directives necessary to activate remote logging.
Along with these other directives, the system can be configured to forward its
logs to a particular log server by adding or correcting one of the following
lines, substituting \"[loghost.example.com]\" appropriately. The choice of
protocol depends on the environment of the system; although TCP and RELP
provide more reliable message delivery, they may not be supported in all
environments.
To use UDP for log message delivery:

*.* @[loghost.example.com]


To use TCP for log message delivery:

*.* @@[loghost.example.com]


To use RELP for log message delivery:

*.* :omrelp:[loghost.example.com]"

  describe file('/etc/rsyslog.conf') do
    its('content') do
      should (match /^\s*\*\.\*\s+@[^@#]+/).or (match /^\s*\*\.\*\s+@@[^@#]+/). or (match /^\s*\*\.\*\s+:omrelp:[^@#]+/)
    end
  end
end
