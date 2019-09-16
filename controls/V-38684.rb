control "V-38684" do
  title "The system must limit users to 10 simultaneous system logins, or a
site-defined number, in accordance with operational requirements."
  desc  "Limiting simultaneous user logins can insulate the system from denial
of service problems caused by excessive logins. Automated login processes
operating improperly or maliciously may result in an exceptional number of
simultaneous login sessions."
  impact 0.3
  tag "gtitle": "SRG-OS-000027"
  tag "gid": "V-38684"
  tag "rid": "SV-50485r2_rule"
  tag "stig_id": "RHEL-06-000319"
  tag "fix_id": "F-43633r1_fix"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]
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
  tag "check": "Run the following command to ensure the \"maxlogins\" value is
configured for all users on the system:

$ grep \"maxlogins\" /etc/security/limits.conf /etc/security/limits.d/*.conf

You should receive output similar to the following:

* hard maxlogins 10

If it is not similar, this is a finding. "
  tag "fix": "Limiting the number of allowed users and sessions per user can
limit risks related to denial of service attacks. This addresses concurrent
sessions for a single account and does not address concurrent sessions by a
single user via multiple accounts. To set the number of concurrent sessions per
user add the following line in \"/etc/security/limits.conf\":

* hard maxlogins 10

A documented site-defined number may be substituted for 10 in the above."

  describe limits_conf do
    its('*') { should include ['hard', 'maxlogins', input('maxlogins').to_s] }
  end
end

