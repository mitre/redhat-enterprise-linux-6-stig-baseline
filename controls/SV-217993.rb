# encoding: UTF-8

control "SV-217993" do
  title "The cron service must be running."
  desc "Due to its usage for maintenance and security-supporting tasks, enabling the cron daemon is essential."
  desc "default", "Due to its usage for maintenance and security-supporting tasks,
enabling the cron daemon is essential."
  desc "check", "Run the following command to determine the current status of the \"crond\" service: 

# service crond status

If the service is enabled, it should return the following: 

crond is running...


If the service is not running, this is a finding."
  desc "fix", "The \"crond\" service is used to execute commands at preconfigured times. It is required by almost all systems to perform necessary maintenance tasks, such as notifying root of system activity. The \"crond\" service can be enabled with the following commands: 

# chkconfig crond on
# service crond start"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217993"
  tag rid: "SV-217993r603264_rule"
  tag stig_id: "RHEL-06-000224"
  tag fix_id: "F-19472r376995_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  describe package("cronie") do
    it { should be_installed }
  end
  describe.one do
    describe service("crond").runlevels(/0/) do
      it { should be_enabled }
    end
    describe service("crond").runlevels(/1/) do
      it { should be_enabled }
    end
    describe service("crond").runlevels(/2/) do
      it { should be_enabled }
    end
    describe service("crond").runlevels(/3/) do
      it { should be_enabled }
    end
    describe service("crond").runlevels(/4/) do
      it { should be_enabled }
    end
    describe service("crond").runlevels(/5/) do
      it { should be_enabled }
    end
    describe service("crond").runlevels(/6/) do
      it { should be_enabled }
    end
  end
end