control "V-38629" do
  title "The graphical desktop environment must set the idle timeout to no more
than 15 minutes."
  desc  "Setting the idle delay controls when the screensaver will start, and
can be combined with screen locking to prevent access from passersby."
  impact 'medium'
  tag "gtitle": "SRG-OS-000029"
  tag "gid": "V-38629"
  tag "rid": "SV-50430r3_rule"
  tag "stig_id": "RHEL-06-000257"
  tag "fix_id": "F-43578r1_fix"
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
  desc 'check', "If the GConf2 package is not installed, this is not applicable.

To check the current idle time-out value, run the following command:

$ gconftool-2 --direct --config-source
xml:readwrite:/etc/gconf/gconf.xml.mandatory --get
/apps/gnome-screensaver/idle_delay

If properly configured, the output should be \"15\".

If it is not, this is a finding."
  desc 'fix', "Run the following command to set the idle time-out value for
inactivity in the GNOME desktop to 15 minutes:

# gconftool-2 \\
--direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type int \\
--set /apps/gnome-screensaver/idle_delay 15"

  if package('GConf2').installed?
    describe command("gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay") do
      its('stdout.strip') { should cmp <= 15 }
    end
  else
    impact 'none'
    describe "Package GConf2 not installed" do
      skip "Package GConf2 not installed, this control Not Applicable"
    end
  end
end

