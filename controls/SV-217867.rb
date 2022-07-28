# encoding: UTF-8

control "SV-217867" do
  title "Default operating system accounts, other than root, must be locked."
  desc "Disabling authentication for default system accounts makes it more difficult for attackers to make use of them to compromise a system."
  desc "default", "Disabling authentication for default system accounts makes it more
difficult for attackers to make use of them to compromise a system."
  desc "check", "To obtain a listing of all users and the contents of their shadow password field, run the command: 

$ awk -F: '$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1 \":\" $2}' /etc/shadow

Identify the operating system accounts from this listing. These will primarily be the accounts with UID numbers less than 500, other than root. 

If any default operating system account (other than root) has a valid password hash, this is a finding."
  desc "fix", "Some accounts are not associated with a human user of the system, and exist to perform some administrative function. An attacker should not be able to log into these accounts. 

Disable logon access to these accounts with the command: 

# passwd -l [SYSACCT]"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000480"
  tag gid: "V-217867"
  tag rid: "SV-217867r603264_rule"
  tag stig_id: "RHEL-06-000029"
  tag fix_id: "F-19346r376617_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]

  passwd_users = command('awk -F: \'$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1}\' /etc/shadow').stdout.strip.split("\n")
  if passwd_users.empty?
    describe "Users with assigned password" do
      subject { passwd_users }
      it { should be_empty }
    end
  else
    passwd_users.each do |u|
      describe user(u) do
        its('uid') { should be >= 500 }
      end
    end
  end
end