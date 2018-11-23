control 'V-38486' do
  title "The operating system must conduct backups of system-level information
contained in the information system per organization defined frequency to
conduct backups that are consistent with recovery time and recovery point
objectives."
  desc  "Operating system backup is a critical step in maintaining data
assurance and availability. System-level information includes system-state
information, operating system and application software, and licenses. Backups
must be consistent with organizational recovery time and recovery point
objectives."
  impact 0.5
  tag "gtitle": 'SRG-OS-000100'
  tag "gid": 'V-38486'
  tag "rid": 'SV-50287r1_rule'
  tag "stig_id": 'RHEL-06-000505'
  tag "fix_id": 'F-43434r1_fix'
  tag "cci": ['CCI-000537']
  tag "nist": ['CP-9b', 'Rev_4']
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
  tag "check": "Ask an administrator if a process exists to back up OS data
from the system, including configuration data.

If such a process does not exist, this is a finding."
  tag "fix": "Procedures to back up OS data from the system must be established
and executed. The Red Hat operating system provides utilities for automating
such a process.  Commercial and open-source products are also available.

Implement a process whereby OS data is backed up from the system in accordance
with local policies."

  describe 'Manual test' do
    skip 'This control must be reviewed manually'
  end
end
