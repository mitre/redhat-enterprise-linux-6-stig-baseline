control "V-38624" do
  title "System logs must be rotated daily."
  desc  "Log files that are not properly rotated run the risk of growing so
large that they fill up the /var/log partition. Valuable logging information
could be lost if the /var/log partition becomes full."
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38624"
  tag "rid": "SV-50425r1_rule"
  tag "stig_id": "RHEL-06-000138"
  tag "fix_id": "F-43573r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "Run the following commands to determine the current status of
the \"logrotate\" service:

# grep logrotate /var/log/cron*

If the logrotate service is not run on a daily basis by cron, this is a
finding."
  tag "fix": "The \"logrotate\" service should be installed or reinstalled if
it is not installed and operating properly, by running the following command:

# yum reinstall logrotate"

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

