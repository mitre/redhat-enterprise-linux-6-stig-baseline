control "V-38478" do
  title "The Red Hat Network Service (rhnsd) service must not be running,
unless using RHN or an RHN Satellite."
  desc  "Although systems management and patching is extremely important to
system security, management by a system outside the enterprise enclave is not
desirable for some environments. However, if the system is being managed by RHN
or RHN Satellite Server the \"rhnsd\" daemon can remain on."
  impact 'low'
  tag "gtitle": "SRG-OS-000096"
  tag "gid": "V-38478"
  tag "rid": "SV-50278r2_rule"
  tag "stig_id": "RHEL-06-000009"
  tag "fix_id": "F-43423r2_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
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
  desc 'check', "If the system uses RHN or an RHN Satellite, this is not
applicable.

To check that the \"rhnsd\" service is disabled in system boot configuration,
run the following command:

# chkconfig \"rhnsd\" --list

Output should indicate the \"rhnsd\" service has either not been installed, or
has been disabled at all runlevels, as shown in the example below:

# chkconfig \"rhnsd\" --list
\"rhnsd\" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify \"rhnsd\" is disabled through current
runtime configuration:

# service rhnsd status

If the service is disabled the command will return the following output:

rhnsd is stopped


If the service is running, this is a finding."
  desc 'fix', "The Red Hat Network service automatically queries Red Hat Network
servers to determine whether there are any actions that should be executed,
such as package updates. This only occurs if the system was registered to an
RHN server or satellite and managed as such. The \"rhnsd\" service can be
disabled with the following commands:

# chkconfig rhnsd off
# service rhnsd stop"

  describe service("rhnsd") do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end

