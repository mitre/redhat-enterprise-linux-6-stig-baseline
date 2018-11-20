control "V-38566" do
  title "The audit system must be configured to audit failed attempts to access
files and programs."
  desc  "Unsuccessful attempts to access files could be an indicator of
malicious activity on a system. Auditing these events could serve as evidence
of potential system compromise."
  impact 0.3
  tag "gtitle": "SRG-OS-000064"
  tag "gid": "V-38566"
  tag "rid": "SV-50367r2_rule"
  tag "stig_id": "RHEL-06-000197"
  tag "fix_id": "F-43514r2_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
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
  tag "check": "To verify that the audit system collects unauthorized file
accesses, run the following commands:

# grep EACCES /etc/audit/audit.rules



# grep EPERM /etc/audit/audit.rules


If either command lacks output, this is a finding."
  tag "fix": "At a minimum, the audit system should collect unauthorized file
accesses for all users and root. Add the following to
\"/etc/audit/audit.rules\", setting ARCH to either b32 or b64 as appropriate
for your system:

-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \\
-S ftruncate -F exit=-EPERM -F auid=0 -k access"

  describe command("grep EACCES /etc/audit/audit.rules") do
    its('stdout.strip') { should_not eq '' }
  end

  describe command("grep EPERM /etc/audit/audit.rules") do
    its('stdout.strip') { should_not eq '' }
  end
end

