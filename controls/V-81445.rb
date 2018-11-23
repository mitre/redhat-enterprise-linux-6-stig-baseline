control 'V-81445' do
  title "The Red Hat Enterprise Linux operating system must mount /dev/shm with
the nodev option."
  desc  "The \"nodev\" mount option causes the system to not interpret
character or block special devices. Executing character or block special
devices from untrusted file systems increases the opportunity for unprivileged
users to attain unauthorized administrative access."
  impact 0.3
  tag "gtitle": 'SRG-OS-000368-GPOS-00154'
  tag "gid": 'V-81445'
  tag "rid": 'SV-96159r1_rule'
  tag "stig_id": 'RHEL-06-000530'
  tag "fix_id": 'F-88263r1_fix'
  tag "cci": ['CCI-001764']
  tag "nist": ['CM-7 (2)', 'Rev_4']
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
  tag "check": "Verify that the \"nodev\" option is configured for /dev/shm.

Check that the operating system is configured to use the \"nodev\" option for
/dev/shm with the following command:

# cat /etc/fstab | grep /dev/shm | grep nodev

tmpfs   /dev/shm   tmpfs   defaults,nodev,nosuid,noexec   0 0

If the \"nodev\" option is not present on the line for \"/dev/shm\", this is a
finding.

Verify \"/dev/shm\" is mounted with the \"nodev\" option:

# mount | grep \"/dev/shm\" | grep nodev

If no results are returned, this is a finding.
"
  tag "fix": "Configure the \"/etc/fstab\" to use the \"nodev\" option for all
lines containing \"/dev/shm\"."

  describe file('/etc/fstab') do
    its('content') { should match(/^[^#\s]+[ \t]+\/dev\/shm[ \t]+[\w\d]+[ \t]+([\w,]+)\s*.*$/) }
  end
  file('/etc/fstab').content.to_s.scan(/^[^#\s]+[ \t]+\/dev\/shm[ \t]+[\w\d]+[ \t]+([\w,]+)\s*.*$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:nodev|[\w,]+,nodev)(?:$|,[\w,]+$)/) }
    end
  end
  describe file('/etc/mtab') do
    its('content') { should match(/^[^#\s]+[ \t]+\/dev\/shm[ \t]+[\w\d]+[ \t]+([\w,]+)\s*.*$/) }
  end
  file('/etc/mtab').content.to_s.scan(/^[^#\s]+[ \t]+\/dev\/shm[ \t]+[\w\d]+[ \t]+([\w,]+)\s*.*$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:nodev|[\w,]+,nodev)(?:$|,[\w,]+$)/) }
    end
  end
end
