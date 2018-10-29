control "V-51391" do
  title "A file integrity baseline must be created."
  desc  "For AIDE to be effective, an initial database of \"known-good\"
information about files must be captured and it should be able to be verified
against the installed files. "
  impact 0.5
  tag "gtitle": "SRG-OS-000232"
  tag "gid": "V-51391"
  tag "rid": "SV-65601r1_rule"
  tag "stig_id": "RHEL-06-000018"
  tag "fix_id": "F-56189r1_fix"
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
  tag "check": "To find the location of the AIDE database file, run the
following command:

# grep DBDIR /etc/aide.conf

Using the defined values of the [DBDIR] and [database] variables, verify the
existence of the AIDE database file:

# ls -l [DBDIR]/[database_file_name]

If there is no database file, this is a finding. "
  tag "fix": "Run the following command to generate a new database:

# /usr/sbin/aide --init

By default, the database will be written to the file
\"/var/lib/aide/aide.db.new.gz\". Storing the database, the configuration file
\"/etc/aide.conf\", and the binary \"/usr/sbin/aide\" (or hashes of these
files), in a secure location (such as on read-only media) provides additional
assurance about their integrity. The newly-generated database can be installed
as follows:

# cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

To initiate a manual check, run the following command:

# /usr/sbin/aide --check

If this check produces any unexpected output, investigate. "

  describe "Manual test" do
    skip "This control must be reviewed manually"
  end
end

