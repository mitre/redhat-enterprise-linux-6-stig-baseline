control 'V-38530' do
  title "The audit system must be configured to audit all attempts to alter
system time through /etc/localtime."
  desc  "Arbitrary changes to the system time can be used to obfuscate
nefarious activities in log files, as well as to confuse network services that
are highly dependent upon an accurate system time (such as sshd). All changes
to the system time should be audited."
  impact 0.3
  tag "gtitle": 'SRG-OS-000062'
  tag "gid": 'V-38530'
  tag "rid": 'SV-50331r2_rule'
  tag "stig_id": 'RHEL-06-000173'
  tag "fix_id": 'F-43477r1_fix'
  tag "cci": ['CCI-000169']
  tag "nist": ['AU-12 a', 'Rev_4']
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
  tag "check": "To determine if the system is configured to audit attempts to
alter time via the /etc/localtime file, run the following command:

$ sudo grep -w \"/etc/localtime\" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

If the system is not configured to audit time changes, this is a finding."
  tag "fix": "Add the following to \"/etc/audit/audit.rules\":

-w /etc/localtime -p wa -k audit_time_rules

The -k option allows for the specification of a key in string form that can be
used for better reporting capability through ausearch and aureport and should
always be used."

  describe file('/etc/audit/audit.rules') do
    its('content') { should match(/^[\s]*-w[\s]+\/etc\/localtime[\s]+-p[\s]+\b([rx]*w[rx]*a[rx]*|[rx]*a[rx]*w[rx]*)\b.*-k[\s]+[\S]+[\s]*$/) }
  end
end
