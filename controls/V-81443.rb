control "V-81443" do
  title "The Red Hat Enterprise Linux operating system must have an anti-virus
solution installed."
  desc  "Virus scanning software can be used to protect a system from
penetration from computer viruses and to limit their spread through
intermediate systems. "
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-81443"
  tag "rid": "SV-96157r1_rule"
  tag "stig_id": "RHEL-06-000533"
  tag "fix_id": "F-88261r1_fix"
  tag "cci": ["CCI-001668"]
  tag "nist": ["SI-3 a", "Rev_4"]
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
  tag "check": "Verify an anti-virus solution is installed on the system. The
anti-virus solution may be bundled with an approved host-based security
solution.

If there is no anti-virus solution installed on the system, this is a finding.
"
  tag "fix": "Install an anti-virus solution on the system. "

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

