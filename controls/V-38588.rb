control "V-38588" do
  title "The system must not permit interactive boot."
  desc  "Using interactive boot, the console user could disable auditing,
firewalls, or other services, weakening system security."
  impact 0.5
  tag "gtitle": "SRG-OS-000080"
  tag "gid": "V-38588"
  tag "rid": "SV-50389r1_rule"
  tag "stig_id": "RHEL-06-000070"
  tag "fix_id": "F-43536r1_fix"
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
  tag "check": "To check whether interactive boot is disabled, run the
following command:

$ grep PROMPT /etc/sysconfig/init

If interactive boot is disabled, the output will show:

PROMPT=no


If it does not, this is a finding."
  tag "fix": "To disable the ability for users to perform interactive startups,
edit the file \"/etc/sysconfig/init\". Add or correct the line:

PROMPT=no

The \"PROMPT\" option allows the console user to perform an interactive system
startup, in which it is possible to select the set of services which are
started on boot."

  describe file("/etc/sysconfig/init") do
    its("content") { should match(/^[\s]*PROMPT[\s]*=[\s]*no[\s]*$/) }
  end
end

