control "V-38651" do
  title "The system default umask for the bash shell must be 077."
  desc  "The umask value influences the permissions assigned to files when they
are created. A misconfigured umask value could result in files with excessive
permissions that can be read and/or written to by unauthorized users."
  impact 'low'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38651"
  tag "rid": "SV-50452r1_rule"
  tag "stig_id": "RHEL-06-000342"
  tag "fix_id": "F-43600r1_fix"
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
  desc 'check', "Verify the \"umask\" setting is configured correctly in the
\"/etc/bashrc\" file by running the following command:

# grep \"umask\" /etc/bashrc

All output must show the value of \"umask\" set to 077, as shown below:

# grep \"umask\" /etc/bashrc
umask 077
umask 077


If the above command returns no output, or if the umask is configured
incorrectly, this is a finding."
  desc 'fix', "To ensure the default umask for users of the Bash shell is set
properly, add or correct the \"umask\" setting in \"/etc/bashrc\" to read as
follows:

umask 077"

  describe file("/etc/bashrc") do
    its("content") { should match(/^[\s]*umask[\s]+([^#\s]*)/) }
  end
  file("/etc/bashrc").content.to_s.scan(/^[\s]*umask[\s]+([^#\s]*)/).flatten.each do |entry|
    describe entry do
      it { should eq "077" }
    end
  end
end

