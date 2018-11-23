control 'V-38473' do
  title 'The system must use a separate file system for user home directories.'
  desc  "Ensuring that \"/home\" is mounted on its own partition enables the
setting of more restrictive mount options, and also helps ensure that users
cannot trivially fill partitions used for log or audit data storage."
  impact 0.3
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-38473'
  tag "rid": 'SV-50273r1_rule'
  tag "stig_id": 'RHEL-06-000007'
  tag "fix_id": 'F-43418r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "Run the following command to determine if \"/home\" is on its
own partition or logical volume:

$ mount | grep \"on /home \"

If \"/home\" has its own partition or volume group, a line will be returned.
If no line is returned, this is a finding."
  tag "fix": "If user home directories will be stored locally, create a
separate partition for \"/home\" at installation time (or migrate it later
using LVM). If \"/home\" will be mounted from another system such as an NFS
server, then creating a separate partition is not necessary at installation
time, and the mountpoint can instead be configured later."

  describe mount('/home') do
    it { should be_mounted }
  end
end
