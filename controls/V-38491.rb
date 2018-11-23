control "V-38491" do
  title "There must be no .rhosts or hosts.equiv files on the system."
  desc  "Trust files are convenient, but when used in conjunction with the
R-services, they can allow unauthenticated access to a system."
  impact 'high'
  tag "gtitle": "SRG-OS-000248"
  tag "gid": "V-38491"
  tag "rid": "SV-50292r1_rule"
  tag "stig_id": "RHEL-06-000019"
  tag "fix_id": "F-43438r1_fix"
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
  desc 'check', "The existence of the file \"/etc/hosts.equiv\" or a file named
\".rhosts\" inside a user home directory indicates the presence of an Rsh trust
relationship.
If these files exist, this is a finding."
  desc 'fix', "The files \"/etc/hosts.equiv\" and \"~/.rhosts\" (in each user's
home directory) list remote hosts and users that are trusted by the local
system when using the rshd daemon. To remove these files, run the following
command to delete them from any location.

# rm /etc/hosts.equiv



$ rm ~/.rhosts"

  describe file("/root/^\\.(r|s)hosts$") do
    it { should_not exist }
  end
  describe command("find /home -regex .\\*/\\^\\\\.\\(r\\|s\\)hosts\\$ -type f  -maxdepth 1") do
    its("stdout") { should be_empty }
  end
  describe file("/etc/^s?hosts\\.equiv$") do
    it { should_not exist }
  end
end

