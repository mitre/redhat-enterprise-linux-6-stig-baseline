control "V-38515" do
  title "The Stream Control Transmission Protocol (SCTP) must be disabled
unless required."
  desc  "Disabling SCTP protects the system against exploitation of any flaws
in its implementation."
  impact 'medium'
  tag "gtitle": "SRG-OS-000096"
  tag "gid": "V-38515"
  tag "rid": "SV-50316r5_rule"
  tag "stig_id": "RHEL-06-000125"
  tag "fix_id": "F-43462r3_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
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
  desc 'check', "If the system is configured to prevent the loading of the
\"sctp\" kernel module, it will contain lines inside any file in
\"/etc/modprobe.d\" or the deprecated\"/etc/modprobe.conf\". These lines
instruct the module loading system to run another program (such as
\"/bin/true\") upon a module \"install\" event. Run the following command to
search for such lines in all files in \"/etc/modprobe.d\" and the deprecated
\"/etc/modprobe.conf\":

$ grep -r sctp /etc/modprobe.conf /etc/modprobe.d | grep -i \"/bin/true\"| grep
-v \"#\"

If no line is returned, this is a finding."
  desc 'fix', "The Stream Control Transmission Protocol (SCTP) is a transport
layer protocol, designed to support the idea of message-oriented communication,
with several streams of messages within one connection. To configure the system
to prevent the \"sctp\" kernel module from being loaded, add the following line
to a file in the directory \"/etc/modprobe.d\":

install sctp /bin/true"

  describe kernel_module('sctp') do
    it { should_not be_loaded }
    it { shold_not be_enabled }
    it { should be_blacklisted }
  end  
end
