control "V-38597" do
  title "The system must limit the ability of processes to have simultaneous
write and execute access to memory."
  desc  "ExecShield uses the segmentation feature on all x86 systems to prevent
execution in memory higher than a certain address. It writes an address as a
limit in the code segment descriptor, to control where code can be executed, on
a per-process basis. When the kernel places a process's memory regions such as
the stack and heap higher than this address, the hardware prevents execution in
that address range."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38597"
  tag "rid": "SV-50398r2_rule"
  tag "stig_id": "RHEL-06-000079"
  tag "fix_id": "F-43545r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
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
  tag "check": "The status of the \"kernel.exec-shield\" kernel parameter can
be queried by running the following command:

$ sysctl kernel.exec-shield
$ grep kernel.exec-shield /etc/sysctl.conf

The output of the command should indicate a value of \"1\". If this value is
not the default value, investigate how it could have been adjusted at runtime,
and verify it is not set improperly in \"/etc/sysctl.conf\".
If the correct value is not returned, this is a finding."
  tag "fix": "To set the runtime status of the \"kernel.exec-shield\" kernel
parameter, run the following command:

# sysctl -w kernel.exec-shield=1

If this is not the system's default value, add the following line to
\"/etc/sysctl.conf\":

kernel.exec-shield = 1"

  describe command('sysctl -n kernel.exec-shield') do
    its('stdout.strip') { should eq '1' }
  end

  describe parse_config_file('/etc/sysctl.conf') do
    its('params') { should be >= { 'kernel.exec-shield' => '1' } }
  end
end

