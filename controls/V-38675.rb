control 'V-38675' do
  title 'Process core dumps must be disabled unless needed.'
  desc  "A core dump includes a memory image taken at the time the operating
system terminates an application. The memory image could contain sensitive data
and is generally useful only for developers trying to debug problems."
  impact 0.3
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38675'
  tag "rid": 'SV-50476r2_rule'
  tag "stig_id": 'RHEL-06-000308'
  tag "fix_id": 'F-43624r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "To verify that core dumps are disabled for all users, run the
following command:

$ grep core /etc/security/limits.conf /etc/security/limits.d/*.conf

The output should be:

* hard core 0

If it is not, this is a finding. "
  tag "fix": "To disable core dumps for all users, add the following line to
\"/etc/security/limits.conf\":

* hard core 0"

  describe limits_conf do
    its('*') { should include %w[hard core 0] }
  end
end
