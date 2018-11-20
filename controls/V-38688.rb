control "V-38688" do
  title "A login banner must be displayed immediately prior to, or as part of,
graphical desktop environment login prompts."
  desc  "An appropriate warning message reinforces policy awareness during the
logon process and facilitates possible legal action against attackers."
  impact 0.5
  tag "gtitle": "SRG-OS-000024"
  tag "gid": "V-38688"
  tag "rid": "SV-50489r3_rule"
  tag "stig_id": "RHEL-06-000324"
  tag "fix_id": "F-43637r2_fix"
  tag "cci": ["CCI-000050"]
  tag "nist": ["AC-8 b", "Rev_4"]
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

To ensure a login warning banner is enabled, run the following:

$ gconftool-2 --direct --config-source
xml:readwrite:/etc/gconf/gconf.xml.mandatory --get
/apps/gdm/simple-greeter/banner_message_enable

Search for the \"banner_message_enable\" schema. If properly configured, the
\"default\" value should be \"true\".
If it is not, this is a finding."
  tag "fix": "To enable displaying a login warning banner in the GNOME Display
Manager's login screen, run the following command:

# gconftool-2 --direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type bool \\
--set /apps/gdm/simple-greeter/banner_message_enable true

To display a banner, this setting must be enabled and then banner text must
also be set."

  if package('GConf2').installed?
    describe command("gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable") do
      its('stdout.strip') { should eq 'true' }
    end
  else
    impact 0.0
    describe "Package GConf2 not installed" do
      skip "Package GConf2 not installed, this control Not Applicable"
    end
  end
end

