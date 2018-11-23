control 'V-38575' do
  title "The audit system must be configured to audit user deletions of files
and programs."
  desc  "Auditing file deletions will create an audit trail for files that are
removed from the system. The audit trail could aid in system troubleshooting,
as well as detecting malicious processes that attempt to delete log files to
conceal their presence."
  impact 0.3
  tag "gtitle": 'SRG-OS-000064'
  tag "gid": 'V-38575'
  tag "rid": 'SV-50376r4_rule'
  tag "stig_id": 'RHEL-06-000200'
  tag "fix_id": 'F-43523r4_fix'
  tag "cci": ['CCI-000172']
  tag "nist": ['AU-12 c', 'Rev_4']
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
  tag "check": "To determine if the system is configured to audit calls to the
\"rmdir\" system call, run the following command:

$ sudo grep -w \"rmdir\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To
determine if the system is configured to audit calls to the \"unlink\" system
call, run the following command:

$ sudo grep -w \"unlink\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To
determine if the system is configured to audit calls to the \"unlinkat\" system
call, run the following command:

$ sudo grep -w \"unlinkat\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To
determine if the system is configured to audit calls to the \"rename\" system
call, run the following command:

$ sudo grep -w \"rename\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To
determine if the system is configured to audit calls to the \"renameat\" system
call, run the following command:

$ sudo grep -w \"renameat\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

If no line is returned, this is a finding. "
  tag "fix": "At a minimum, the audit system should collect file deletion
events for all users and root. Add the following (or equivalent) to
\"/etc/audit/audit.rules\", setting ARCH to either b32 or b64 as appropriate
for your system:

-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S
renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S
renameat -F auid=0 -k delete

"

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)rmdir(?:,|\s+).*-F\s+auid>=500\s+-F\s+auid!=(?:(?:-1)|(?:4294967295))\s+-k\s+\S+\s*$/) }
  end
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)unlink(?:,|\s+).*-F\s+auid>=500\s+-F\s+auid!=(?:(?:-1)|(?:4294967295))\s+-k\s+\S+\s*$/) }
  end
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)unlinkat(?:,|\s+).*-F\s+auid>=500\s+-F\s+auid!=(?:(?:-1)|(?:4294967295))\s+-k\s+\S+\s*$/) }
  end
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)rename(?:,|\s+).*-F\s+auid>=500\s+-F\s+auid!=(?:(?:-1)|(?:4294967295))\s+-k\s+\S+\s*$/) }
  end
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)renameat(?:,|\s+).*-F\s+auid>=500\s+-F\s+auid!=(?:(?:-1)|(?:4294967295))\s+-k\s+\S+\s*$/) }
  end
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)rmdir(?:,|\s+).*-F\s+auid=0\s+-k\s+\S+\s*$/) }
  end
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)unlink(?:,|\s+).*-F\s+auid=0\s+-k\s+\S+\s*$/) }
  end
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)unlinkat(?:,|\s+).*-F\s+auid=0\s+-k\s+\S+\s*$/) }
  end
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)rename(?:,|\s+).*-F\s+auid=0\s+-k\s+\S+\s*$/) }
  end
  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-a[\s](?:always,exit|exit,always)\s+(?:-F\s+arch=b32\s+).*(?:,|-S\s+)renameat(?:,|\s+).*-F\s+auid=0\s+-k\s+\S+\s*$/) }
  end
  describe.one do
  end
end
