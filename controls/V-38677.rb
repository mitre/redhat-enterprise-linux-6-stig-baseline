control "V-38677" do
  title "The NFS server must not have the insecure file locking option enabled."
  desc  "Allowing insecure file locking could allow for sensitive data to be
viewed or edited by an unauthorized user."
  impact 'high'
  tag "gtitle": "SRG-OS-000104"
  tag "gid": "V-38677"
  tag "rid": "SV-50478r1_rule"
  tag "stig_id": "RHEL-06-000309"
  tag "fix_id": "F-43626r1_fix"
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
  desc 'check', "To verify insecure file locking has been disabled, run the
following command:

# grep insecure_locks /etc/exports


If there is output, this is a finding."
  desc 'fix', "By default the NFS server requires secure file-lock requests,
which require credentials from the client in order to lock a file. Most NFS
clients send credentials with file lock requests, however, there are a few
clients that do not send credentials when requesting a file-lock, allowing the
client to only be able to lock world-readable files. To get around this, the
\"insecure_locks\" option can be used so these clients can access the desired
export. This poses a security risk by potentially allowing the client access to
data for which it does not have authorization. Remove any instances of the
\"insecure_locks\" option from the file \"/etc/exports\"."

  describe file("/etc/exports") do
    its("content") { should_not match(/^[^#]*insecure_locks.*$/) }
  end
end

