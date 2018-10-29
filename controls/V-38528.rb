control "V-38528" do
  title "The system must log Martian packets."
  desc  "The presence of \"martian\" packets (which have impossible addresses)
as well as spoofed packets, source-routed packets, and redirects could be a
sign of nefarious network activity. Logging these packets enables this activity
to be detected."
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38528"
  tag "rid": "SV-50329r2_rule"
  tag "stig_id": "RHEL-06-000088"
  tag "fix_id": "F-43476r1_fix"
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
  tag "check": "The status of the \"net.ipv4.conf.all.log_martians\" kernel
parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.log_martians

The output of the command should indicate a value of \"1\". If this value is
not the default value, investigate how it could have been adjusted at runtime,
and verify it is not set improperly in \"/etc/sysctl.conf\".

$ grep net.ipv4.conf.all.log_martians /etc/sysctl.conf

If the correct value is not returned, this is a finding. "
  tag "fix": "To set the runtime status of the
\"net.ipv4.conf.all.log_martians\" kernel parameter, run the following command:

# sysctl -w net.ipv4.conf.all.log_martians=1

If this is not the system's default value, add the following line to
\"/etc/sysctl.conf\":

net.ipv4.conf.all.log_martians = 1"

  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should eq 1 }
  end
  describe file("/etc/sysctl.conf") do
    its("content") { should match(/^[\s]*net.ipv4.conf.all.log_martians[\s]*=[\s]*1[\s]*$/) }
  end
end

