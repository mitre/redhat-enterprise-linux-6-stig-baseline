control "V-38674" do
  title "X Windows must not be enabled unless required."
  desc  "Unnecessary services should be disabled to decrease the attack surface
of the system."
  impact 'medium'
  tag "gtitle": "SRG-OS-000248"
  tag "gid": "V-38674"
  tag "rid": "SV-50475r1_rule"
  tag "stig_id": "RHEL-06-000290"
  tag "fix_id": "F-43623r1_fix"
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
  desc 'check', "To verify the default runlevel is 3, run the following command:

# grep initdefault /etc/inittab

The output should show the following:

id:3:initdefault:


If it does not, this is a finding."
  desc 'fix', "Setting the system's runlevel to 3 will prevent automatic startup
of the X server. To do so, ensure the following line in \"/etc/inittab\"
features a \"3\" as shown:

id:3:initdefault:"

  describe file("/etc/inittab") do
    its("content") { should match(/^[\s]*id:3:initdefault:[\s]*$/) }
  end
end

