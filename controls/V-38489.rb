control 'V-38489' do
  title 'A file integrity tool must be installed.'
  desc  "The AIDE package must be installed if it is to be available for
integrity checking."
  impact 0.5
  tag "gtitle": 'SRG-OS-000232'
  tag "gid": 'V-38489'
  tag "rid": 'SV-50290r1_rule'
  tag "stig_id": 'RHEL-06-000016'
  tag "fix_id": 'F-43436r1_fix'
  tag "cci": ['CCI-001069']
  tag "nist": ['RA-5 (7)', 'Rev_4']
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
  tag "check": "If another file integrity tool is installed, this is not a
finding.

Run the following command to determine if the \"aide\" package is installed:

# rpm -q aide


If the package is not installed, this is a finding."
  tag "fix": "Install the AIDE package with the command:

# yum install aide"

  describe package('aide') do
    it { should be_installed }
  end
end
