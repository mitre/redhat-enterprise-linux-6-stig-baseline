control "V-38638" do
  title "The graphical desktop environment must have automatic lock enabled."
  desc  "Enabling the activation of the screen lock after an idle period
ensures password entry will be required in order to access the system,
preventing access by passersby."
  impact 0.5
  tag "gtitle": "SRG-OS-000029"
  tag "gid": "V-38638"
  tag "rid": "SV-50439r3_rule"
  tag "stig_id": "RHEL-06-000259"
  tag "fix_id": "F-43587r1_fix"
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

To check the status of the idle screen lock activation, run the following
command:

$ gconftool-2 --direct --config-source
xml:readwrite:/etc/gconf/gconf.xml.mandatory --get
/apps/gnome-screensaver/lock_enabled

If properly configured, the output should be \"true\".
If it is not, this is a finding."
  tag "fix": "Run the following command to activate locking of the screensaver
in the GNOME desktop when it is activated:

# gconftool-2 --direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type bool \\
--set /apps/gnome-screensaver/lock_enabled true"

  describe "SCAP oval resource xmlfilecontent_test is not yet supported." do
    skip "SCAP oval resource xmlfilecontent_test is not yet supported."
  end
end

