control "V-38602" do
  title "The rlogind service must not be running."
  desc  "The rlogin service uses unencrypted network communications, which
means that data from the login session, including passwords and all other
information transmitted during the session, can be stolen by eavesdroppers on
the network."
  impact 0.7
  tag "gtitle": "SRG-OS-000248"
  tag "gid": "V-38602"
  tag "rid": "SV-50403r2_rule"
  tag "stig_id": "RHEL-06-000218"
  tag "fix_id": "F-43549r3_fix"
  tag "cci": ["CCI-001436"]
  tag "nist": ["AC-17 (8)", "Rev_4"]
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
  tag "check": "
To check that the \"rlogin\" service is disabled in system boot configuration,
run the following command:

# chkconfig \"rlogin\" --list

Output should indicate the \"rlogin\" service has either not been installed, or
has been disabled, as shown in the example below:

# chkconfig \"rlogin\" --list
rlogin off
OR
error reading information on service rlogin: No such file or directory


If the service is running, this is a finding."
  tag "fix": "The \"rlogin\" service, which is available with the
\"rsh-server\" package and runs as a service through xinetd, should be
disabled. The \"rlogin\" service can be disabled with the following command:

# chkconfig rlogin off"

  describe.one do
    describe package("rsh-server") do
      it { should_not be_installed }
    end
    describe file("/etc/xinetd.d/rlogin") do
      its("content") { should match(/^\s*disable\s+=\s+yes\s*$/) }
    end
  end
end

