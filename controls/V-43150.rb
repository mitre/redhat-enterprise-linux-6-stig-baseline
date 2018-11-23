control 'V-43150' do
  title 'The login user list must be disabled.'
  desc  "Leaving the user list enabled is a security risk since it allows
anyone with physical access to the system to quickly enumerate known user
accounts without logging in."
  impact 0.5
  tag "gtitle": 'SRG-OS-999999'
  tag "gid": 'V-43150'
  tag "rid": 'SV-55880r2_rule'
  tag "stig_id": 'RHEL-06-000527'
  tag "fix_id": 'F-48722r2_fix'
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
  tag "check": "If the GConf2 package is not installed, this is not applicable.

To ensure the user list is disabled, run the following command:

$ gconftool-2 --direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--get /apps/gdm/simple-greeter/disable_user_list

The output should be \"true\". If it is not, this is a finding. "
  tag "fix": "In the default graphical environment, users logging directly into
the system are greeted with a login screen that displays all known users. This
functionality should be disabled.

Run the following command to disable the user list:

$ sudo gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool --set /apps/gdm/simple-greeter/disable_user_list true"

  if package('GConf2').installed?
    describe command('gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/disable_user_list') do
      its('stdout.strip') { should eq 'true' }
    end
  else
    impact 0.0
    describe 'Package GConf2 not installed' do
      skip 'Package GConf2 not installed, this control Not Applicable'
    end
  end
end
