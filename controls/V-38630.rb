control "V-38630" do
  title "The graphical desktop environment must automatically lock after 15
minutes of inactivity and the system must require user reauthentication to
unlock the environment."
  desc  "Enabling idle activation of the screen saver ensures the screensaver
will be activated after the idle delay. Applications requiring continuous,
real-time screen display (such as network management products) require the
login session does not have administrator rights and the display station is
located in a controlled-access area."
  impact 0.5
  tag "gtitle": "SRG-OS-000029"
  tag "gid": "V-38630"
  tag "rid": "SV-50431r3_rule"
  tag "stig_id": "RHEL-06-000258"
  tag "fix_id": "F-43579r1_fix"
  tag "cci": ["CCI-000057"]
  tag "nist": ["AC-11 a", "Rev_4"]
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

To check the screensaver mandatory use status, run the following command:

$ gconftool-2 --direct --config-source
xml:readwrite:/etc/gconf/gconf.xml.mandatory --get
/apps/gnome-screensaver/idle_activation_enabled

If properly configured, the output should be \"true\".

If it is not, this is a finding."
  tag "fix": "Run the following command to activate the screensaver in the
GNOME desktop after a period of inactivity:

# gconftool-2 --direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type bool \\
--set /apps/gnome-screensaver/idle_activation_enabled true"

  if package('GConf2').installed?
    describe command("gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled") do
      its('stdout.strip') { should eq 'true' }
    end
  else
    impact 0.0
    describe "Package GConf2 not installed" do
      skip "Package GConf2 not installed, this control Not Applicable"
    end
  end
end

