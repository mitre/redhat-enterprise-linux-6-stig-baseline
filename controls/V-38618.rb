control "V-38618" do
  title "The avahi service must be disabled."
  desc  "Because the Avahi daemon service keeps an open network port, it is
subject to network attacks. Its functionality is convenient but is only
appropriate if the local network can be trusted."
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38618"
  tag "rid": "SV-50419r2_rule"
  tag "stig_id": "RHEL-06-000246"
  tag "fix_id": "F-43567r2_fix"
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
  tag "check": "To check that the \"avahi-daemon\" service is disabled in
system boot configuration, run the following command:

# chkconfig \"avahi-daemon\" --list

Output should indicate the \"avahi-daemon\" service has either not been
installed, or has been disabled at all runlevels, as shown in the example
below:

# chkconfig \"avahi-daemon\" --list
\"avahi-daemon\" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"avahi-daemon\" is disabled through
current runtime configuration:

# service avahi-daemon status

If the service is disabled the command will return the following output:

avahi-daemon is stopped


If the service is running, this is a finding."
  tag "fix": "The \"avahi-daemon\" service can be disabled with the following
commands:

# chkconfig avahi-daemon off
# service avahi-daemon stop"

  describe service("avahi-daemon").runlevels(/0/) do
    it { should_not be_enabled }
  end
  describe service("avahi-daemon").runlevels(/1/) do
    it { should_not be_enabled }
  end
  describe service("avahi-daemon").runlevels(/2/) do
    it { should_not be_enabled }
  end
  describe service("avahi-daemon").runlevels(/3/) do
    it { should_not be_enabled }
  end
  describe service("avahi-daemon").runlevels(/4/) do
    it { should_not be_enabled }
  end
  describe service("avahi-daemon").runlevels(/5/) do
    it { should_not be_enabled }
  end
  describe service("avahi-daemon").runlevels(/6/) do
    it { should_not be_enabled }
  end
end

