# encoding: UTF-8

control "SV-217869" do
  title "The /etc/passwd file must not contain password hashes."
  desc "The hashes for all user account passwords should be stored in the file \"/etc/shadow\" and never in \"/etc/passwd\", which is readable by all users."
  desc "default", "The hashes for all user account passwords should be stored in the file
\"/etc/shadow\" and never in \"/etc/passwd\", which is readable by all users."
  desc "check", "To check that no password hashes are stored in \"/etc/passwd\", run the following command: 

# awk -F: '($2 != \"x\") {print}' /etc/passwd

If it produces any output, then a password hash is stored in \"/etc/passwd\". 
If any stored hashes are found in /etc/passwd, this is a finding."
  desc "fix", "If any password hashes are stored in \"/etc/passwd\" (in the second field, instead of an \"x\"), the cause of this misconfiguration should be investigated. The account should have its password reset and the hash should be properly stored, or the account should be deleted entirely."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000073"
  tag gid: "V-217869"
  tag rid: "SV-217869r603264_rule"
  tag stig_id: "RHEL-06-000031"
  tag fix_id: "F-19348r376623_fix"
  tag cci: ["CCI-000366", "CCI-000196"]
  tag nist: ["CM-6 b", "Rev_4", "IA-5 (1) (c)"]

  describe file("/etc/passwd") do
    its("content") { should match(/^[^:]*:([^:]*):/) }
  end
  file("/etc/passwd").content.to_s.scan(/^[^:]*:([^:]*):/).flatten.each do |entry|
    describe entry do
      it { should eq "x" }
    end
  end
end