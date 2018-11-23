control "V-38699" do
  title "All public directories must be owned by a system account."
  desc  "Allowing a user account to own a world-writable directory is
undesirable because it allows the owner of that directory to remove or replace
any files that may be placed in the directory by other users."
  impact 'low'
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38699"
  tag "rid": "SV-50500r2_rule"
  tag "stig_id": "RHEL-06-000337"
  tag "fix_id": "F-43648r1_fix"
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
  desc 'check', "The following command will discover and print world-writable
directories that are not owned by a system account, given the assumption that
only system accounts have a uid lower than 500. Run it once for each local
partition [PART]:

# find [PART] -xdev -type d -perm -0002 -uid +499 -print


If there is output, this is a finding."
  desc 'fix', "All directories in local partitions which are world-writable
should be owned by root or another system account. If any world-writable
directories are not owned by a system account, this should be investigated.
Following this, the files should be deleted or assigned to an appropriate
group."

  dirs = command(%(find / -xautofs -noleaf -wholename '/proc' -prune -o -wholename '/sys' -prune -o -wholename '/dev' -prune -o -wholename '/selinux' -prune -o -type d -perm -0002 -uid +499 -print))
  describe "World-writable directories not owned by system account" do
    subject { dirs.stdout.strip.split("\n") }
    it { should be_empty }
  end
end

