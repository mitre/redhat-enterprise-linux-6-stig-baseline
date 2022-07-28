# encoding: UTF-8

control "SV-217941" do
  title "The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited."
  desc "A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise."
  desc "default", "A log server (loghost) receives syslog messages from one or more
systems. This data can be used as an additional log source in the event a
system is compromised and its local logs are suspect. Forwarding log messages
to a remote loghost also provides system administrators with a centralized
place to view the status of multiple hosts within the enterprise."
  desc "check", "To ensure logs are sent to a remote host, examine the file \"/etc/rsyslog.conf\". If using UDP, a line similar to the following should be present: 

*.* @[loghost.example.com]

If using TCP, a line similar to the following should be present: 

*.* @@[loghost.example.com]

If using RELP, a line similar to the following should be present: 

*.* :omrelp:[loghost.example.com]


If none of these are present, this is a finding."
  desc "fix", "To configure rsyslog to send logs to a remote log server, open \"/etc/rsyslog.conf\" and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting \"[loghost.example.com]\" appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments. 
To use UDP for log message delivery: 

*.* @[loghost.example.com]


To use TCP for log message delivery: 

*.* @@[loghost.example.com]


To use RELP for log message delivery: 

*.* :omrelp:[loghost.example.com]"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000215"
  tag gid: "V-217941"
  tag rid: "SV-217941r603264_rule"
  tag stig_id: "RHEL-06-000136"
  tag fix_id: "F-19420r376839_fix"
  tag cci: ["CCI-001348"]
  tag nist: ["AU-9 (2)", "Rev_4"]

  describe file('/etc/rsyslog.conf') do
    its('content') {
      should (match %r{^\s*\*\.\*\s+@[^@#]+}).or (match %r{^\s*\*\.\*\s+@@[^@#]+}). or (match %r{^\s*\*\.\*\s+:omrelp:[^@#]+})
    }
  end
end