control "V-38567" do
  title "The audit system must be configured to audit all use of setuid and
setgid programs."
  desc  "Privileged programs are subject to escalation-of-privilege attacks,
which attempt to subvert their normal role of providing some necessary but
limited capability. As such, motivation exists to monitor these programs for
unusual activity."
  impact 'low'
  tag "gtitle": "SRG-OS-000020"
  tag "gid": "V-38567"
  tag "rid": "SV-50368r4_rule"
  tag "stig_id": "RHEL-06-000198"
  tag "fix_id": "F-43515r6_fix"
  tag "cci": ["CCI-000040"]
  tag "nist": ["AC-6 (2)", "Rev_4"]
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
  desc 'check', "To verify that auditing of privileged command use is
configured, run the following command once for each local partition [PART] to
find relevant setuid / setgid programs:

$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null

Run the following command to verify entries in the audit rules for all programs
found with the previous command:

$ sudo grep path /etc/audit/audit.rules

It should be the case that all relevant setuid / setgid programs have a line in
the audit rules. If that is not the case, this is a finding. "
  desc 'fix', "At a minimum, the audit system should collect the execution of
privileged commands for all users and root. To find the relevant setuid /
setgid programs, run the following command for each local partition [PART]:

$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null

Then, for each setuid / setgid program on the system, add a line of the
following form to \"/etc/audit/audit.rules\", where [SETUID_PROG_PATH] is the
full path to each setuid / setgid program in the list:

-a always,exit -F path=[SETUID_PROG_PATH] -F perm=x -F auid>=500 -F
auid!=4294967295 -k privileged"

  files = command(%(find / -xautofs -noleaf -wholename '/proc' -prune -o -wholename '/sys' -prune -o -wholename '/dev' -prune -o -wholename '/selinux' -prune -o -type f -perm /6000 -print)).stdout.strip.split("\n")
  
  if files.empty?
    describe "setuid and setgid files" do
      subject { files }
      it { should be_empty }
    end
  else
    files.each do |f|
      describe auditd do
        its('lines') { should include match "path=#{f}" }
      end
    end
  end
end

