control "V-38460" do
  title "The NFS server must not have the all_squash option enabled."
  desc  "The \"all_squash\" option maps all client requests to a single
anonymous uid/gid on the NFS server, negating the ability to track file access
by user ID."
  impact 'low'
  tag "gtitle": "SRG-OS-000104"
  tag "gid": "V-38460"
  tag "rid": "SV-50260r1_rule"
  tag "stig_id": "RHEL-06-000515"
  tag "fix_id": "F-43405r1_fix"
  tag "cci": ["CCI-000764"]
  tag "nist": ["IA-2", "Rev_4"]
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
  desc 'check', "If the NFS server is read-only, in support of unrestricted
access to organizational content, this is not applicable.

The related \"root_squash\" option provides protection against remote
administrator-level access to NFS server content.  Its use is not a finding.

To verify the \"all_squash\" option has been disabled, run the following
command:

# grep all_squash /etc/exports


If there is output, this is a finding."
  desc 'fix', "Remove any instances of the \"all_squash\" option from the file
\"/etc/exports\".  Restart the NFS daemon for the changes to take effect.

# service nfs restart"

  describe command("grep all_squash /etc/exports") do
    its('stdout.strip') { should be_empty }
  end
end

