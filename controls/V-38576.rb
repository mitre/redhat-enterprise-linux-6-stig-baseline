control "V-38576" do
  title "The system must use a FIPS 140-2 approved cryptographic hashing
algorithm for generating account password hashes (login.defs)."
  desc  "Using a stronger hashing algorithm makes password cracking attacks
more difficult."
  impact 0.5
  tag "gtitle": "SRG-OS-000120"
  tag "gid": "V-38576"
  tag "rid": "SV-50377r1_rule"
  tag "stig_id": "RHEL-06-000063"
  tag "fix_id": "F-43524r1_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]
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
  tag "check": "Inspect \"/etc/login.defs\" and ensure the following line
appears:

ENCRYPT_METHOD SHA512


If it does not, this is a finding."
  tag "fix": "In \"/etc/login.defs\", add or correct the following line to
ensure the system will use SHA-512 as the hashing algorithm:

ENCRYPT_METHOD SHA512"

  describe file("/etc/login.defs") do
    its("content") { should match(/^[\s]*ENCRYPT_METHOD[\s]+SHA512[\s]*$/) }
  end
end

