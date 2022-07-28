# encoding: UTF-8

control "SV-217936" do
  title "The Reliable Datagram Sockets (RDS) protocol must be disabled unless required."
  desc "Disabling RDS protects the system against exploitation of any flaws in its implementation."
  desc "default", "Disabling RDS protects the system against exploitation of any flaws in
its implementation."
  desc "check", "If the system is configured to prevent the loading of the \"rds\" kernel module, it will contain lines inside any file in \"/etc/modprobe.d\" or the deprecated \"/etc/modprobe.conf\". These lines instruct the module loading system to run another program (such as \"/bin/true\") upon a module \"install\" event. Run the following command to search for such lines in all files in \"/etc/modprobe.d\" and the deprecated \"/etc/modprobe.conf\": 

$ grep -r rds /etc/modprobe.conf /etc/modprobe.d

If no line is returned, this is a finding."
  desc "fix", "The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide reliable high-bandwidth, low-latency communications between nodes in a cluster. To configure the system to prevent the \"rds\" kernel module from being loaded, add the following line to a file in the directory \"/etc/modprobe.d\": 

install rds /bin/true"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000096"
  tag gid: "V-217936"
  tag rid: "SV-217936r603264_rule"
  tag stig_id: "RHEL-06-000126"
  tag fix_id: "F-19415r376824_fix"
  tag cci: ["CCI-000382"]
  tag nist: ["CM-7 b", "Rev_4"]

  describe kernel_module('rds') do
    it { should_not be_loaded }
    it { shold_not be_enabled }
    it { should be_blacklisted }
  end
end