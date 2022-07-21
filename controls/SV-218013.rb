# encoding: UTF-8

control "SV-218013" do
  title "The graphical desktop environment must have automatic lock enabled."
  desc "Enabling the activation of the screen lock after an idle period ensures password entry will be required in order to access the system, preventing access by passersby."
  desc "default", "Enabling the activation of the screen lock after an idle period
ensures password entry will be required in order to access the system,
preventing access by passersby."
  desc "check", "If the GConf2 package is not installed, this is not applicable. 

To check the status of the idle screen lock activation, run the following command: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled

If properly configured, the output should be \"true\". 
If it is not, this is a finding."
  desc "fix", "Run the following command to activate locking of the screensaver in the GNOME desktop when it is activated: 

# gconftool-2 --direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type bool \\
--set /apps/gnome-screensaver/lock_enabled true"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000029"
  tag gid: "V-218013"
  tag rid: "SV-218013r603264_rule"
  tag stig_id: "RHEL-06-000259"
  tag fix_id: "F-19492r377055_fix"
  tag cci: ["CCI-000057"]
  tag nist: ["AC-11 a", "Rev_4"]

  if package('GConf2').installed?
    describe command("gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled") do
      its('stdout.strip') { should eq 'true' }
    end
  else
    impact 0.0
    describe "Package GConf2 not installed" do
      skip "Package GConf2 not installed, this control Not Applicable"
    end
  end
end