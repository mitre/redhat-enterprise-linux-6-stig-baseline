control 'V-38678' do
  title "The audit system must provide a warning when allocated audit record
storage volume reaches a documented percentage of maximum audit record storage
capacity."
  desc  "Notifying administrators of an impending disk space problem may allow
them to take corrective action prior to any disruption."
  impact 0.5
  tag "gtitle": 'SRG-OS-000048'
  tag "gid": 'V-38678'
  tag "rid": 'SV-50479r2_rule'
  tag "stig_id": 'RHEL-06-000311'
  tag "fix_id": 'F-43627r2_fix'
  tag "cci": ['CCI-000143']
  tag "nist": ['AU-5 (1)', 'Rev_4']
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
  tag "check": "Review the \"/etc/audit/auditd.conf\" and locate the following
line to determine whether the system is configured to email the administrator
when disk space is starting to run low:

# grep space_left /etc/audit/auditd.conf

space_left = [num_megabytes]


If the \"num_megabytes\" value does not correspond to a documented value for
remaining audit partition capacity or if there is no locally documented value
for remaining audit partition capacity, this is a finding.
  If the value of the \"space_left\" keyword is not set to 25 percent of the
total partition size, this is a finding."
  tag "fix": "The \"auditd\" service can be configured to take an action when
disk space starts to run low. Edit the file \"/etc/audit/auditd.conf\". Modify
the following line, substituting [num_megabytes] appropriately:

space_left = [num_megabytes]

The \"num_megabytes\" value should be set to a fraction of the total audit
storage capacity available that will allow a system administrator to be
notified with enough time to respond to the situation causing the capacity
issues.  This value must also be documented locally."

  describe auditd_conf do
    before(:all) do
      @audit_log_dir = File.dirname(auditd_conf.log_file)

      if file(@audit_log_dir).directory?
        partition_info = command("df -h #{@audit_log_dir}").stdout.split("\n")

        partition_sz_arr = partition_info.last.gsub(/\s+/m, ' ').strip.split(' ')

        # Get partition size in GB
        partition_sz = partition_sz_arr[1].delete('G')

        # Convert to MB and get 25%
        @exp_space_left = partition_sz.to_i * 1024 / 4
      end
    end

    it 'should have an audit log directory' do
      expect(file(@audit_log_dir).directory?).to be true
    end

    its('space_left.to_i') { should be >= @exp_space_left }
  end
end
