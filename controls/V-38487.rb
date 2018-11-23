control 'V-38487' do
  title "The system package management tool must cryptographically verify the
authenticity of all software packages during installation."
  desc  "Ensuring all packages' cryptographic signatures are valid prior to
installation ensures the provenance of the software and protects against
malicious tampering."
  impact 0.3
  tag "gtitle": 'SRG-OS-000103'
  tag "gid": 'V-38487'
  tag "rid": 'SV-50288r1_rule'
  tag "stig_id": 'RHEL-06-000015'
  tag "fix_id": 'F-43433r1_fix'
  tag "cci": ['CCI-000663']
  tag "nist": ['SA-7', 'Rev_4']
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
  tag "check": "To determine whether \"yum\" has been configured to disable
\"gpgcheck\" for any repos, inspect all files in \"/etc/yum.repos.d\" and
ensure the following does not appear in any sections:

gpgcheck=0

A value of \"0\" indicates that \"gpgcheck\" has been disabled for that repo.
If GPG checking is disabled, this is a finding.

If the \"yum\" system package management tool is not used to update the system,
verify with the SA that installed packages are cryptographically signed."
  tag "fix": "To ensure signature checking is not disabled for any repos,
remove any lines from files in \"/etc/yum.repos.d\" of the form:

gpgcheck=0"

  command('find /etc/yum.repos.d -type f -regex .\\*/.\\*').stdout.split.each do |entry|
    describe file(entry) do
      its('content') { should_not match(/^\s*gpgcheck\s*=\s*0\s*$/) }
    end
  end
end
