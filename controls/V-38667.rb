control "V-38667" do
  title "The system must have a host-based intrusion detection tool installed."
  desc  "Adding host-based intrusion detection tools can provide the capability
to automatically take actions in response to malicious behavior, which can
provide additional agility in reacting to network threats. These tools also
often include a reporting capability to provide network awareness of system,
which may not otherwise exist in an organization's systems management regime."
  impact 0.5
  tag "gtitle": "SRG-OS-000196"
  tag "gid": "V-38667"
  tag "rid": "SV-50468r3_rule"
  tag "stig_id": "RHEL-06-000285"
  tag "fix_id": "F-43616r3_fix"
  tag "cci": ["CCI-001263"]
  tag "nist": ["SI-4 (5)", "Rev_4"]
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
  tag "check": "Ask the SA or ISSO if a host-based intrusion detection
application is loaded on the system. Per OPORD 16-0080 the preferred intrusion
detection system is McAfee HBSS available through Cybercom.

If another host-based intrusion detection application is in use, such as
SELinux, this must be documented and approved by the local Authorizing Official.

Procedure:
Examine the system to see if the Host Intrusion Prevention System (HIPS) is
installed:

# rpm -qa | grep MFEhiplsm

Verify that the McAfee HIPS module is active on the system:

# ps -ef | grep -i “hipclient”

If the MFEhiplsm package is not installed, check for another intrusion
detection system:

# find / -name <daemon name>

Where <daemon name> is the name of the primary application daemon to determine
if the application is loaded on the system.

Determine if the application is active on the system:

# ps -ef | grep -i <daemon name>

If the MFEhiplsm package is not installed and an alternate host-based intrusion
detection application has not been documented for use, this is a finding.

If no host-based intrusion detection system is installed and running on the
system, this is a finding.
"
  tag "fix": "Install and enable the latest McAfee HIPS package, available from
Cybercom.

If the system does not support the McAfee HIPS package, install and enable a
supported intrusion detection system application and document its use with the
Authorizing Official.
"

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

