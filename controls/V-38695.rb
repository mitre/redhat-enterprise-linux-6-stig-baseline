control "V-38695" do
  title "A file integrity tool must be used at least weekly to check for
unauthorized file changes, particularly the addition of unauthorized system
libraries or binaries, or for unauthorized modification to authorized system
libraries or binaries."
  desc  "By default, AIDE does not install itself for periodic execution.
Periodically running AIDE may reveal unexpected changes in installed files."
  impact 0.5
  tag "gtitle": "SRG-OS-000094"
  tag "gid": "V-38695"
  tag "rid": "SV-50496r2_rule"
  tag "stig_id": "RHEL-06-000302"
  tag "fix_id": "F-43644r1_fix"
  tag "cci": ["CCI-000374"]
  tag "nist": ["CM-6 (2)", "Rev_4"]
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

If there is no output or if aide is not run at least weekly, this is a finding."
  tag "fix": "AIDE should be executed on a periodic basis to check for changes.
To implement a daily execution of AIDE at 4:05am using cron, add the following
line to /etc/crontab:

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one
example."

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

