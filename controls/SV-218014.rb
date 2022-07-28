# encoding: UTF-8

control "SV-218014" do
  title "The system must display a publicly-viewable pattern during a graphical desktop environment session lock."
  desc "Setting the screensaver mode to blank-only conceals the contents of the display from passersby."
  desc "default", "Setting the screensaver mode to blank-only conceals the contents of
the display from passersby."
  desc "check", "If the GConf2 package is not installed, this is not applicable. 

To ensure the screensaver is configured to be blank, run the following command: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode

If properly configured, the output should be \"blank-only\". 
If it is not, this is a finding."
  desc "fix", "Run the following command to set the screensaver mode in the GNOME desktop to a blank screen: 

# gconftool-2 \\
--direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type string \\
--set /apps/gnome-screensaver/mode blank-only"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000031"
  tag gid: "V-218014"
  tag rid: "SV-218014r603264_rule"
  tag stig_id: "RHEL-06-000260"
  tag fix_id: "F-19493r377058_fix"
  tag cci: ["CCI-000060"]
  tag nist: ["AC-11 (1)", "Rev_4"]

  if package('GConf2').installed?
    describe command("gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode") do
      its('stdout.strip') { should eq 'blank-only' }
    end
  else
    impact 0.0
    describe "Package GConf2 not installed" do
      skip "Package GConf2 not installed, this control Not Applicable"
    end
  end
end