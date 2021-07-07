control "V-38586" do
  title "The system must require authentication upon booting into single-user
and maintenance modes."
  desc  "This prevents attackers with physical access from trivially bypassing
security on the machine and gaining root access. Such accesses are further
prevented by configuring the bootloader password."
  impact 'medium'
  tag "gtitle": "SRG-OS-000080"
  tag "gid": "V-38586"
  tag "rid": "SV-50387r1_rule"
  tag "stig_id": "RHEL-06-000069"
  tag "fix_id": "F-43534r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
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
  desc 'check', "To check if authentication is required for single-user mode,
run the following command:

$ grep SINGLE /etc/sysconfig/init

The output should be the following:

SINGLE=/sbin/sulogin


If the output is different, this is a finding."
  desc 'fix', "Single-user mode is intended as a system recovery method,
providing a single user root access to the system by providing a boot option at
startup. By default, no authentication is performed if single-user mode is
selected.

To require entry of the root password even if the system is started in
single-user mode, add or correct the following line in the file
\"/etc/sysconfig/init\":

SINGLE=/sbin/sulogin"

  describe file("/etc/sysconfig/init") do
    its("content") { should match(/^SINGLE=\/sbin\/sulogin[\s]*/) }
  end
end

