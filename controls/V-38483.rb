control "V-38483" do
  title "The system package management tool must cryptographically verify the
authenticity of system software packages during installation."
  desc  "Ensuring the validity of packages' cryptographic signatures prior to
installation ensures the provenance of the software and protects against
malicious tampering."
  impact 0.5
  tag "gtitle": "SRG-OS-000103"
  tag "gid": "V-38483"
  tag "rid": "SV-50283r1_rule"
  tag "stig_id": "RHEL-06-000013"
  tag "fix_id": "F-43429r1_fix"
  tag "cci": ["CCI-000663"]
  tag "nist": ["SA-7", "Rev_4"]
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
  tag "check": "To determine whether \"yum\" is configured to use \"gpgcheck\",
inspect \"/etc/yum.conf\" and ensure the following appears in the \"[main]\"
section:

gpgcheck=1

A value of \"1\" indicates that \"gpgcheck\" is enabled. Absence of a
\"gpgcheck\" line or a setting of \"0\" indicates that it is disabled.
If GPG checking is not enabled, this is a finding.

If the \"yum\" system package management tool is not used to update the system,
verify with the SA that installed packages are cryptographically signed."
  tag "fix": "The \"gpgcheck\" option should be used to ensure checking of an
RPM package's signature always occurs prior to its installation. To configure
yum to check package signatures before installing them, ensure the following
line appears in \"/etc/yum.conf\" in the \"[main]\" section:

gpgcheck=1"

  describe file("/etc/yum.conf") do
    its("content") { should match(/^\s*gpgcheck\s*=\s*1\s*$/) }
  end
end

