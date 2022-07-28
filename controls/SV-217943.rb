# encoding: UTF-8

control "SV-217943" do
  title "System logs must be rotated daily."
  desc "Log files that are not properly rotated run the risk of growing so large that they fill up the /var/log partition. Valuable logging information could be lost if the /var/log partition becomes full."
  desc "default", "Log files that are not properly rotated run the risk of growing so
large that they fill up the /var/log partition. Valuable logging information
could be lost if the /var/log partition becomes full."
  desc "check", "Run the following commands to determine the current status of the \"logrotate\" service: 

# grep logrotate /var/log/cron*

If the logrotate service is not run on a daily basis by cron, this is a finding."
  desc "fix", "The \"logrotate\" service should be installed or reinstalled if it is not installed and operating properly, by running the following command:

# yum reinstall logrotate"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217943"
  tag rid: "SV-217943r603264_rule"
  tag stig_id: "RHEL-06-000138"
  tag fix_id: "F-19422r376845_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  # TODO is this too specific?
  describe bash("grep logrotate /var/log/cron*") do
    its('stdout.strip') { should match %r{cron\.daily} }
  end
end