#
# Cookbook Name:: openstack-network
# Recipe:: common
#
# Copyright 2013, AT&T
# Copyright 2013, SUSE Linux GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require "uri"

class ::Chef::Recipe
  include ::Openstack
end

platform_options = node["openstack"]["network"]["platform"]

driver_name = node["openstack"]["network"]["interface_driver"].split('.').last.downcase
main_plugin = node["openstack"]["network"]["interface_driver_map"][driver_name]
core_plugin = node["openstack"]["network"]["core_plugin"]

if node["openstack"]["network"]["syslog"]["use"]
  include_recipe "openstack-common::logging"
end

platform_options["nova_network_packages"].each do |pkg|
  package pkg do
    action :purge
  end
end

platform_options["quantum_packages"].each do |pkg|
  package pkg do
    action :install
  end
end

directory "/etc/quantum/plugins" do
  recursive true
  owner node["openstack"]["network"]["platform"]["user"]
  group node["openstack"]["network"]["platform"]["group"]
  mode 00700
  action :create
end

directory "/var/cache/quantum" do
  owner node["openstack"]["network"]["platform"]["user"]
  group node["openstack"]["network"]["platform"]["group"]
  mode 00700
  action :create
end

directory ::File.dirname node["openstack"]["network"]["api"]["auth"]["cache_dir"] do
  owner node["openstack"]["network"]["platform"]["user"]
  group node["openstack"]["network"]["platform"]["group"]
  mode 00700

  only_if { node["openstack"]["auth"]["strategy"] == "pki" }
end

# This will copy recursively all the files in
# /files/default/etc/quantum/rootwrap.d
remote_directory "/etc/quantum/rootwrap.d" do
  source "etc/quantum/rootwrap.d"
  files_owner node["openstack"]["network"]["platform"]["user"]
  files_group node["openstack"]["network"]["platform"]["group"]
  files_mode 00700
end

template "/etc/quantum/rootwrap.conf" do
  source "rootwrap.conf.erb"
  owner node["openstack"]["network"]["platform"]["user"]
  group node["openstack"]["network"]["platform"]["group"]
  mode 00644
end



platform_options["quantum_client_packages"].each do |pkg|
  package pkg do
    action :upgrade
    options platform_options["package_overrides"]
  end
end



directory "/etc/quantum/plugins/#{main_plugin}" do
  recursive true
  owner node["openstack"]["network"]["platform"]["user"]
  group node["openstack"]["network"]["platform"]["group"]
  mode 00700
end

