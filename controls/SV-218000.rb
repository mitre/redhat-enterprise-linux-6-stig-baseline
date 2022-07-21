# encoding: UTF-8

control "SV-218000" do
  title "The system must not permit root logins using remote access programs such as ssh."
  desc "Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root's password."
  desc "default", "Permitting direct root login reduces auditable information about who
ran privileged commands on the system and also allows direct attack attempts on
root's password."
  desc "check", "To determine how the SSH daemon's \"PermitRootLogin\" option is set, run the following command: 

# grep -i PermitRootLogin /etc/ssh/sshd_config

If a line indicating \"no\" is returned, then the required value is set. 
If the required value is not set, this is a finding."
  desc "fix", "The root user should never be allowed to log in to a system directly over a network. To disable root login via SSH, add or correct the following line in \"/etc/ssh/sshd_config\": 

PermitRootLogin no"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000109"
  tag gid: "V-218000"
  tag rid: "SV-218000r603264_rule"
  tag stig_id: "RHEL-06-000237"
  tag fix_id: "F-19479r377016_fix"
  tag cci: ["CCI-000770"]
  tag nist: ["IA-2 (5)", "Rev_4"]

  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
  end
end