# encoding: utf-8

# copyright: 2015, The Authors
# license: All rights reserved

title 'falco section'

control 'falco -1.0' do # A unique ID for this control
  impact 0.7 # The criticality, if this control fails.
  title 'falco should be present'
  desc 'Ensure Falco executable and configuration are present'
  describe file('/etc/falco') do
    it { should be_directory }
    it { should be_owned_by 'root' }
    its('mode') { should cmp '0700' }
  end
  describe file('/etc/falco/falco.yaml') do
    it { should be_file }
    it { should be_owned_by 'root' }
    its('mode') { should cmp '0600' }
  end
  describe file('/etc/falco/falco_rules.yaml') do
    it { should be_file }
    it { should be_owned_by 'root' }
    its('mode') { should cmp '0600' }
  end
  describe file('/usr/bin/falco') do
    it { should be_file }
    it { should be_executable }
    it { should be_owned_by 'root' }
  end
end

control 'falco-2.0' do
  impact 0.7
  title 'falco should be running'
  desc 'Ensure falco is running'
  only_if { !(virtualization.role == 'guest' && (virtualization.system == 'docker' or virtualization.system == 'lxd')) }
  describe processes('falco') do
    it { should exist }
    its('users') { should eq ['root'] }
    its('list.length') { should eq 1 }
  end
end

control 'falco-3.0' do
  impact 0.7
  title 'falco should have log files'
  desc 'Ensure falco logs are present'
  only_if { !(virtualization.role == 'guest' && (virtualization.system == 'docker' or virtualization.system == 'lxd')) }
  if os.redhat?
    describe file('/var/log/messages') do
      its('content') { should match 'falco: Loading rules from file ' }
      its('content') { should match 'falco_probe: CPU buffer initialized' }
      its('content') { should match 'falco_probe: starting capture' }
    end
  else
    describe file('/var/log/syslog') do
      its('content') { should match 'falco: Loading rules from file ' }
      its('content') { should match 'falco_probe: CPU buffer initialized' }
      its('content') { should match 'falco_probe: starting capture' }
    end
  end
end
