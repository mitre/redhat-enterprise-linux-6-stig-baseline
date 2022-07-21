# encoding: UTF-8

control "SV-217907" do
  title "The system must be configured so that all network connections associated with a communication session are terminated at the end of the session or after 15 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements."
  desc "Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session."
  desc "default", "Installing \"screen\" ensures a console locking capability is
available for users who may need to suspend console logins."
  desc "check", "Verify the operating system terminates all network connections associated with a communications session at the end of the session or based on inactivity.

Check the value of the system inactivity timeout with the following command:

# grep -i tmout /etc/profile.d/*

etc/profile.d/tmout.sh:TMOUT=900

/etc/profile.d/tmout.sh:readonly TMOUT

/etc/profile.d/tmout.sh:export TMOUT

If \"TMOUT\" is not set to \"900\" or less in a script located in the /etc/profile.d/ directory to enforce session termination after inactivity, this is a finding."
  desc "fix", "Configure the operating system to terminate all network connections associated with a communications session at the end of the session or after a period of inactivity.

Create a script to enforce the inactivity timeout (for example /etc/profile.d/tmout.sh) such as:

#!/bin/bash

TMOUT=900
readonly TMOUT
export TMOUT"
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag gtitle: "SRG-OS-000030"
  tag gid: "V-217907"
  tag rid: "SV-217907r603264_rule"
  tag stig_id: "RHEL-06-000071"
  tag fix_id: "F-19386r462508_fix"
  tag cci: ["CCI-000058", "CCI-000057", "CCI-001133", "CCI-002361"]
  tag nist: ["AC-11 a", "Rev_4", "SC-10", "AC-12"]

  describe package("screen") do
    it { should be_installed }
  end
end