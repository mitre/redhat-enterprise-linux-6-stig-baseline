control "V-38437" do
  title "Automated file system mounting tools must not be enabled unless
needed."
  desc  "All filesystems that are required for the successful operation of the
system should be explicitly listed in \"/etc/fstab\" by an administrator. New
filesystems should not be arbitrarily introduced via the automounter.

    The \"autofs\" daemon mounts and unmounts filesystems, such as user home
directories shared via NFS, on demand. In addition, autofs can be used to
handle removable media, and the default configuration provides the cdrom device
as \"/misc/cd\". However, this method of providing access to removable media is
not common, so autofs can almost always be disabled if NFS is not in use. Even
if NFS is required, it is almost always possible to configure filesystem mounts
statically by editing \"/etc/fstab\" rather than relying on the automounter.
  "
  impact 0.3
  tag "gtitle": "SRG-OS-999999"
  tag "gid": "V-38437"
  tag "rid": "SV-50237r1_rule"
  tag "stig_id": "RHEL-06-000526"
  tag "fix_id": "F-43381r1_fix"
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
  tag "check": "To verify the \"autofs\" service is disabled, run the following
command:

chkconfig --list autofs

If properly configured, the output should be the following:

autofs 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Verify the \"autofs\" service is not running:

# service autofs status

If the autofs service is enabled or running, this is a finding."
  tag "fix": "If the \"autofs\" service is not needed to dynamically mount NFS
filesystems or removable media, disable the service for all runlevels:

# chkconfig --level 0123456 autofs off

Stop the service if it is already running:

# service autofs stop"

  describe service("autofs").runlevels(/0/) do
    it { should_not be_enabled }
  end
  describe service("autofs").runlevels(/1/) do
    it { should_not be_enabled }
  end
  describe service("autofs").runlevels(/2/) do
    it { should_not be_enabled }
  end
  describe service("autofs").runlevels(/3/) do
    it { should_not be_enabled }
  end
  describe service("autofs").runlevels(/4/) do
    it { should_not be_enabled }
  end
  describe service("autofs").runlevels(/5/) do
    it { should_not be_enabled }
  end
  describe service("autofs").runlevels(/6/) do
    it { should_not be_enabled }
  end
end

