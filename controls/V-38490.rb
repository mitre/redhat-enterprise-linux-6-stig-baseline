control "V-38490" do
  title "The operating system must enforce requirements for the connection of
mobile devices to operating systems."
  desc  "USB storage devices such as thumb drives can be used to introduce
unauthorized software and other vulnerabilities. Support for these devices
should be disabled and the devices themselves should be tightly controlled."
  impact 'medium'
  tag "gtitle": "SRG-OS-000273"
  tag "gid": "V-38490"
  tag "rid": "SV-50291r6_rule"
  tag "stig_id": "RHEL-06-000503"
  tag "fix_id": "F-43437r3_fix"
  tag "cci": ["CCI-000086"]
  tag "nist": ["AC-19 d", "Rev_4"]
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
  desc 'check', "If the system is configured to prevent the loading of the
\"usb-storage\" kernel module, it will contain lines inside any file in
\"/etc/modprobe.d\" or the deprecated\"/etc/modprobe.conf\". These lines
instruct the module loading system to run another program (such as
\"/bin/true\") upon a module \"install\" event. Run the following command to
search for such lines in all files in \"/etc/modprobe.d\" and the deprecated
\"/etc/modprobe.conf\":

$ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d | grep -i \"/bin/true\"
| grep -v \"#\"

If no line is returned, this is a finding."
  desc 'fix', "To prevent USB storage devices from being used, configure the
kernel module loading system to prevent automatic loading of the USB storage
driver. To configure the system to prevent the \"usb-storage\" kernel module
from being loaded, add the following line to a file in the directory
\"/etc/modprobe.d\":

install usb-storage /bin/true

This will prevent the \"modprobe\" program from loading the \"usb-storage\"
module, but will not prevent an administrator (or another program) from using
the \"insmod\" program to load the module manually."

  describe.one do
    command("find /etc/modprobe.d -type f -regex .\\*/\\^.\\*\\\\.conf\\$").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\s*install\s+usb-storage\s+(\/bin\/true)\s*$/) }
      end
    end
    describe file("/etc/modprobe.conf") do
      its("content") { should match(/^\s*install\s+usb-storage\s+(\/bin\/true)\s*$/) }
    end
  end
end

