control "V-38568" do
  title "The audit system must be configured to audit successful file system
mounts."
  desc  "The unauthorized exportation of data to external media could result in
an information leak where classified information, Privacy Act information, and
intellectual property could be lost. An audit trail should be created each time
a filesystem is mounted to help identify and guard against information loss."
  impact 'low'
  tag "gtitle": "SRG-OS-000064"
  tag "gid": "V-38568"
  tag "rid": "SV-50369r3_rule"
  tag "stig_id": "RHEL-06-000199"
  tag "fix_id": "F-43516r2_fix"
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
  desc 'check', "To verify that auditing is configured for all media exportation
events, run the following command:

$ sudo grep -w \"mount\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several
lines.

If no line is returned, this is a finding. "
  desc 'fix', "At a minimum, the audit system should collect media exportation
events for all users and root. Add the following to \"/etc/audit/audit.rules\",
setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=ARCH -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=ARCH -S mount -F auid=0 -k export"

  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^[\s]*-a[\s]+(?:always,exit|exit,always)\s+(-F\s+arch=b32\s+).*(?:,|-S\s+)mount(?:,|\s+).*-F\s+auid>=500\s+-F\s+auid!=(?:4294967295|-1)\s+-k\s+\S+\s*$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^[\s]*-a[\s]+(?:always,exit|exit,always)\s+(-F\s+arch=b64\s+).*(?:,|-S\s+)mount(?:,|\s+).*-F\s+auid>=500\s+-F\s+auid!=(?:4294967295|-1)\s+-k\s+\S+\s*$/) }
  end
  describe.one do
    
  end
end

