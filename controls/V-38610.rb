control "V-38610" do
  title "The SSH daemon must set a timeout count on idle sessions."
  desc  "This ensures a user login will be terminated as soon as the
\"ClientAliveCountMax\" is reached."
  impact 0.3
  tag "gtitle": "SRG-OS-000126"
  tag "gid": "V-38610"
  tag "rid": "SV-50411r1_rule"
  tag "stig_id": "RHEL-06-000231"
  tag "fix_id": "F-43558r1_fix"
  tag "cci": ["CCI-000879"]
  tag "nist": ["MA-4 e", "Rev_4"]
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
  tag "check": "To ensure the SSH idle timeout will occur when the
\"ClientAliveCountMax\" is set, run the following command:

# grep ClientAliveCountMax /etc/ssh/sshd_config

If properly configured, output should be:

ClientAliveCountMax 0


If it is not, this is a finding."
  tag "fix": "To ensure the SSH idle timeout occurs precisely when the
\"ClientAliveCountMax\" is set, edit \"/etc/ssh/sshd_config\" as follows:

ClientAliveCountMax 0"

  describe sshd_config do
    its('ClientAliveCountMax') { should cmp 0 }
  end
end

