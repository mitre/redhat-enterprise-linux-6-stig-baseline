# encoding: UTF-8

control "SV-217899" do
  title "The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs)."
  desc "Using a stronger hashing algorithm makes password cracking attacks more difficult."
  desc "default", "Using a stronger hashing algorithm makes password cracking attacks
more difficult."
  desc "check", "Inspect \"/etc/login.defs\" and ensure the following line appears: 

ENCRYPT_METHOD SHA512


If it does not, this is a finding."
  desc "fix", "In \"/etc/login.defs\", add or correct the following line to ensure the system will use SHA-512 as the hashing algorithm: 

ENCRYPT_METHOD SHA512"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000120"
  tag gid: "V-217899"
  tag rid: "SV-217899r603264_rule"
  tag stig_id: "RHEL-06-000063"
  tag fix_id: "F-19378r376713_fix"
  tag cci: ["CCI-000803"]
  tag nist: ["IA-7", "Rev_4"]

  describe file("/etc/login.defs") do
    its("content") { should match(/^[\s]*ENCRYPT_METHOD[\s]+SHA512[\s]*$/) }
  end
end