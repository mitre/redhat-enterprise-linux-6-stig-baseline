control "V-38682" do
  title "The Bluetooth kernel module must be disabled."
  desc  "If Bluetooth functionality must be disabled, preventing the kernel
from loading the kernel module provides an additional safeguard against its
activation."
  impact 0.5
  tag "gtitle": "SRG-OS-000034"
  tag "gid": "V-38682"
  tag "rid": "SV-50483r5_rule"
  tag "stig_id": "RHEL-06-000315"
  tag "fix_id": "F-43631r3_fix"
  tag "cci": ["CCI-000085"]
  tag "nist": ["AC-19 c", "Rev_4"]
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
  tag "check": "If the system is configured to prevent the loading of the
\"bluetooth\" kernel module, it will contain lines inside any file in
\"/etc/modprobe.d\" or the deprecated\"/etc/modprobe.conf\". These lines
instruct the module loading system to run another program (such as
\"/bin/true\") upon a module \"install\" event. Run the following command to
search for such lines in all files in \"/etc/modprobe.d\" and the deprecated
\"/etc/modprobe.conf\":

$ grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d | grep -i \"/bin/true\"|
grep -v \"#\"

If no line is returned, this is a finding.

If the system is configured to prevent the loading of the \"net-pf-31\" kernel
module, it will contain lines inside any file in \"/etc/modprobe.d\" or the
deprecated\"/etc/modprobe.conf\". These lines instruct the module loading
system to run another program (such as \"/bin/true\") upon a module \"install\"
event. Run the following command to search for such lines in all files in
\"/etc/modprobe.d\" and the deprecated \"/etc/modprobe.conf\":

$ grep -r net-pf-31 /etc/modprobe.conf /etc/modprobe.d | grep -i \"/bin/true\" |
grep -v \"#\"

If no line is returned, this is a finding."
  tag "fix": "The kernel's module loading system can be configured to prevent
loading of the Bluetooth module. Add the following to the appropriate
\"/etc/modprobe.d\" configuration file to prevent the loading of the Bluetooth
module:

install net-pf-31 /bin/true
install bluetooth /bin/true"

  describe command("grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d | grep -i \"/bin/true\" | grep -v \"#\"") do
    its('stdout.strip') { should_not be_empty }
  end

  describe command("grep -r net-pf-31 /etc/modprobe.conf /etc/modprobe.d | grep -i \"/bin/true\" | grep -v \"#\"") do
    its('stdout.strip') { should_not be_empty }
  end
end

