control 'V-38673' do
  title "The operating system must ensure unauthorized, security-relevant
configuration changes detected are tracked."
  desc  "By default, AIDE does not install itself for periodic execution.
Periodically running AIDE may reveal unexpected changes in installed files."
  impact 0.5
  tag "gtitle": 'SRG-OS-000265'
  tag "gid": 'V-38673'
  tag "rid": 'SV-50474r2_rule'
  tag "stig_id": 'RHEL-06-000307'
  tag "fix_id": 'F-43621r1_fix'
  tag "cci": ['CCI-001589']
  tag "nist": ['CM-6 (3)', 'Rev_4']
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
  tag "check": "To determine that periodic AIDE execution has been scheduled,
run the following command:

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding."
  tag "fix": "AIDE should be executed on a periodic basis to check for changes.
To implement a daily execution of AIDE at 4:05am using cron, add the following
line to /etc/crontab:

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one
example."

  describe command('grep aide /etc/crontab /etc/cron.*/*') do
    its('stdout.strip') { should_not be_empty }
  end
end
