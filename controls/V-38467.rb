control 'V-38467' do
  title "The system must use a separate file system for the system audit data
path."
  desc  "Placing \"/var/log/audit\" in its own partition enables better
separation between audit files and other files, and helps ensure that auditing
cannot be halted due to the partition running out of space."
  impact 0.3
  tag "gtitle": 'SRG-OS-000044'
  tag "gid": 'V-38467'
  tag "rid": 'SV-50267r1_rule'
  tag "stig_id": 'RHEL-06-000004'
  tag "fix_id": 'F-43412r1_fix'
  tag "cci": ['CCI-000137']
  tag "nist": ['AU-4', 'Rev_4']
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
  tag "check": "Run the following command to determine if \"/var/log/audit\" is
on its own partition or logical volume:

$ mount | grep \"on /var/log/audit \"

If \"/var/log/audit\" has its own partition or volume group, a line will be
returned.
If no line is returned, this is a finding."
  tag "fix": "Audit logs are stored in the \"/var/log/audit\" directory. Ensure
that it has its own partition or logical volume at installation time, or
migrate it later using LVM. Make absolutely certain that it is large enough to
store all audit logs that will be created by the auditing daemon."

  describe mount('/var/log/audit') do
    it { should be_mounted }
  end
end
