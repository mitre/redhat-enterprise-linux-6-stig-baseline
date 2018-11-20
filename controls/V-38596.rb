control "V-38596" do
  title "The system must implement virtual address space randomization."
  desc  "Address space layout randomization (ASLR) makes it more difficult for
an attacker to predict the location of attack code he or she has introduced
into a process's address space during an attempt at exploitation. Additionally,
ASLR also makes it more difficult for an attacker to know the location of
existing code in order to repurpose it using return oriented programming (ROP)
techniques."
  impact 0.5
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38596"
  tag "rid": "SV-50397r2_rule"
  tag "stig_id": "RHEL-06-000078"
  tag "fix_id": "F-43543r1_fix"
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
  tag "check": "The status of the \"kernel.randomize_va_space\" kernel
parameter can be queried by running the following commands:

$ sysctl kernel.randomize_va_space
$ grep kernel.randomize_va_space /etc/sysctl.conf

The output of the command should indicate a value of at least \"1\" (preferably
\"2\"). If this value is not the default value, investigate how it could have
been adjusted at runtime, and verify it is not set improperly in
\"/etc/sysctl.conf\".
If the correct value is not returned, this is a finding."
  tag "fix": "To set the runtime status of the \"kernel.randomize_va_space\"
kernel parameter, run the following command:

# sysctl -w kernel.randomize_va_space=2

If this is not the system's default value, add the following line to
\"/etc/sysctl.conf\":

kernel.randomize_va_space = 2"

  describe command('sysctl -n kernel.randomize_va_space') do
    its('stdout.strip') { should be_in ['1', '2'] }
  end

  describe.one do
    describe parse_config_file('/etc/sysctl.conf') do
      its('params') { should be >= { 'kernel.randomize_va_space' => '1' } }
    end

    describe parse_config_file('/etc/sysctl.conf') do
      its('params') { should be >= { 'kernel.randomize_va_space' => '2' } }
    end
  end
end

