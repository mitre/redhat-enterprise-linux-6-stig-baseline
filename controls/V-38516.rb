control "V-38516" do
  title "The Reliable Datagram Sockets (RDS) protocol must be disabled unless
required."
  desc  "Disabling RDS protects the system against exploitation of any flaws in
its implementation."
  impact 'low'
  tag "gtitle": "SRG-OS-000096"
  tag "gid": "V-38516"
  tag "rid": "SV-50317r3_rule"
  tag "stig_id": "RHEL-06-000126"
  tag "fix_id": "F-43463r4_fix"
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
\"rds\" kernel module, it will contain lines inside any file in
\"/etc/modprobe.d\" or the deprecated \"/etc/modprobe.conf\". These lines
instruct the module loading system to run another program (such as
\"/bin/true\") upon a module \"install\" event. Run the following command to
search for such lines in all files in \"/etc/modprobe.d\" and the deprecated
\"/etc/modprobe.conf\":

$ grep -r rds /etc/modprobe.conf /etc/modprobe.d

If no line is returned, this is a finding."
  desc 'fix', "The Reliable Datagram Sockets (RDS) protocol is a transport layer
protocol designed to provide reliable high-bandwidth, low-latency
communications between nodes in a cluster. To configure the system to prevent
the \"rds\" kernel module from being loaded, add the following line to a file
in the directory \"/etc/modprobe.d\":

install rds /bin/true"

  describe.one do
    command("find /etc/modprobe.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\s*install\s+rds\s+(\/bin\/true)\s*$/) }
      end
    end
    describe file("/etc/modprobe.conf") do
      its("content") { should match(/^\s*install\s+rds\s+(\/bin\/true)\s*$/) }
    end
  end
end

