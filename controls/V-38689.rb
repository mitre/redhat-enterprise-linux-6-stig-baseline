control "V-38689" do
  title "The Department of Defense (DoD) login banner must be displayed
immediately prior to, or as part of, graphical desktop environment login
prompts."
  desc  "An appropriate warning message reinforces policy awareness during the
logon process and facilitates possible legal action against attackers."
  impact 'medium'
  tag "gtitle": "SRG-OS-000228"
  tag "gid": "V-38689"
  tag "rid": "SV-50490r5_rule"
  tag "stig_id": "RHEL-06-000326"
  tag "fix_id": "F-43638r5_fix"
  tag "cci": ["CCI-001384", "CCI-001385", "CCI-001386", "CCI-001387",
"CCI-001388"]
  tag "nist": ["AC-8 c 1", "AC-8 c 2", "AC-8 c 2", "AC-8 c 2", "AC-8 c 3",
"Rev_4"]
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

To ensure login warning banner text is properly set, run the following:

$ gconftool-2 --direct --config-source
xml:readwrite:/etc/gconf/gconf.xml.mandatory --get
/apps/gdm/simple-greeter/banner_message_text

If properly configured, the proper banner text will appear within this schema.

The DoD required text is either:

\"You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only. By using this IS (which includes any
device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject
to routine monitoring, interception, and search, and may be disclosed or used
for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls)
to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE
or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.\"

OR:

\"I've read & consent to terms in IS user agreem't.\"

If the DoD required banner text does not appear in the schema, this is a
finding."
  desc 'fix', "To set the text shown by the GNOME Display Manager in the login
screen, run the following command:

# gconftool-2
--direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type string \\
--set /apps/gdm/simple-greeter/banner_message_text \\
\"[DoD required text]\"

Where the DoD required text is either:

\"You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only. By using this IS (which includes any
device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject
to routine monitoring, interception, and search, and may be disclosed or used
for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls)
to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE
or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.\"

OR:

\"I've read & consent to terms in IS user agreem't.\"

When entering a warning banner that spans several lines, remember to begin and
end the string with \"\"\". This command writes directly to the file
\"/etc/gconf/gconf.xml.mandatory/apps/gdm/simple-greeter/%gconf.xml\", and this
file can later be edited directly if necessary."

  if package('GConf2').installed?
    banner_text = command("gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_text").stdout.strip.gsub(%r{[\r\n\s]}, '')
    describe "gconf2 banner text" do
      subject { banner_text }
      it { should eq input('banner_text').gsub(%r{[\r\n\s]}, '') }
    end
  else
    impact 'none'
    describe "Package GConf2 not installed" do
      skip "Package GConf2 not installed, this control Not Applicable"
    end
  end
end

