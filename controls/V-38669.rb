control "V-38669" do
  title "The postfix service must be enabled for mail delivery."
  desc  "Local mail delivery is essential to some system maintenance and
notification tasks."
  impact 'low'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38669"
  tag "rid": "SV-50470r1_rule"
  tag "stig_id": "RHEL-06-000287"
  tag "fix_id": "F-43618r1_fix"
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
  desc 'check', "Run the following command to determine the current status of
the \"postfix\" service:

# service postfix status

If the service is enabled, it should return the following:

postfix is running...

If the service is not enabled, this is a finding."
  desc 'fix', "The Postfix mail transfer agent is used for local mail delivery
within the system. The default configuration only listens for connections to
the default SMTP port (port 25) on the loopback interface (127.0.0.1). It is
recommended to leave this service enabled for local mail delivery. The
\"postfix\" service can be enabled with the following command:

# chkconfig postfix on
# service postfix start"

  describe package("postfix") do
    it { should be_installed }
  end
  describe.one do
    describe service("postfix").runlevels(/0/) do
      it { should be_enabled }
    end
    describe service("postfix").runlevels(/1/) do
      it { should be_enabled }
    end
    describe service("postfix").runlevels(/2/) do
      it { should be_enabled }
    end
    describe service("postfix").runlevels(/3/) do
      it { should be_enabled }
    end
    describe service("postfix").runlevels(/4/) do
      it { should be_enabled }
    end
    describe service("postfix").runlevels(/5/) do
      it { should be_enabled }
    end
    describe service("postfix").runlevels(/6/) do
      it { should be_enabled }
    end
  end
end

