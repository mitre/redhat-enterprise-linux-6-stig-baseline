# encoding: UTF-8

control "SV-217859" do
  title "A file integrity baseline must be created."
  desc "For AIDE to be effective, an initial database of \"known-good\" information about files must be captured and it should be able to be verified against the installed files."
  desc "default", "For AIDE to be effective, an initial database of \"known-good\"
information about files must be captured and it should be able to be verified
against the installed files."
  desc "check", "To find the location of the AIDE database file, run the following command:

# grep DBDIR /etc/aide.conf

Using the defined values of the [DBDIR] and [database] variables, verify the existence of the AIDE database file:

# ls -l [DBDIR]/[database_file_name]

If there is no database file, this is a finding."
  desc "fix", "Run the following command to generate a new database:

# /usr/sbin/aide --init

By default, the database will be written to the file \"/var/lib/aide/aide.db.new.gz\". Storing the database, the configuration file \"/etc/aide.conf\", and the binary \"/usr/sbin/aide\" (or hashes of these files), in a secure location (such as on read-only media) provides additional assurance about their integrity. The newly-generated database can be installed as follows:

# cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

To initiate a manual check, run the following command:

# /usr/sbin/aide --check

If this check produces any unexpected output, investigate."
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000363"
  tag gid: "V-217859"
  tag rid: "SV-217859r603264_rule"
  tag stig_id: "RHEL-06-000018"
  tag fix_id: "F-19338r376593_fix"
  tag cci: ["CCI-000366", "CCI-001774"]
  tag nist: ["CM-6 b", "Rev_4", "CM-7 (5) (b)"]

  database = parse_config_file('/etc/aide.conf').params['database']
  if database.nil?
    describe "aide.conf database variable" do
      subject { nil }
      it { should_not be_nil }
    end
  else
    # find the constants which are used by the database variable
    defines = database.match('@@{([A-Z,a-z]+)}')
    if defines.nil?
      defines = []
    else
      defines = defines.captures
    end
    # lookup the values of the constants used by the database variable
    aide_conf_file = file('/etc/aide.conf')
    defines_map = defines.map do |d|
      define_match = aide_conf_file.content.match("^\\s*@@define\\s*#{d}\\s*(\\S*)\\s*$")
      define_value = if define_match.nil? then nil else define_match.captures[0] end
      [d, define_value]
    end.to_h.reject { |k,v| v.nil? }
    # substitute the constants names in the database variable with their values
    defines_map.each { |k,v| database.gsub!("@@{#{k}}", v) }
    database.gsub!(%r{^file:}, '')
    describe file(database) do
      it { should exist }
      it { should be_file }
    end
  end
end