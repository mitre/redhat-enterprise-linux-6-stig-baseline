control "V-38469" do
  title "All system command files must have mode 755 or less permissive."
  desc  "System binaries are executed by privileged users, as well as system
services, and restrictive permissions are necessary to ensure execution of
these programs cannot be co-opted."
  impact 0.5
  tag "gtitle": "SRG-OS-000259"
  tag "gid": "V-38469"
  tag "rid": "SV-50269r3_rule"
  tag "stig_id": "RHEL-06-000047"
  tag "fix_id": "F-43414r1_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
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
  tag "check": "System executables are stored in the following directories by
default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

All files in these directories should not be group-writable or world-writable.
To find system executables that are group-writable or world-writable, run the
following command for each directory [DIR] which contains system executables:

$ find -L [DIR] -perm /022 -type f

If any system executables are found to be group-writable or world-writable,
this is a finding."
  tag "fix": "System executables are stored in the following directories by
default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

If any file in these directories is found to be group-writable or
world-writable, correct its permission with the following command:

# chmod go-w [FILE]"

  describe "SCAP oval resource file_test could not be loaded: Don't understand SCAP::OVAL::States: file_state/type" do
    skip "SCAP oval resource file_test could not be loaded: Don't understand SCAP::OVAL::States: file_state/type"
  end
end

