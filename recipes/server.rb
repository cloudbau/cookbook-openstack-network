#
# Cookbook Name:: openstack-network
# Recipe:: server
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

class ::Chef::Recipe
  include ::Openstack
end

include_recipe "openstack-network::common"

platform_options = node["openstack"]["network"]["platform"]
driver_name = node["openstack"]["network"]["interface_driver"].split('.').last.downcase
main_plugin = node["openstack"]["network"]["interface_driver_map"][driver_name]
core_plugin = node["openstack"]["network"]["core_plugin"]

platform_options = node["openstack"]["network"]["platform"]

(platform_options["quantum_server_packages"] + platform_options["mysql_python_packages"]).each do |pkg|
  package pkg do
    options platform_options["package_overrides"]
    action :install
  end
end

rabbit_server_role = node["openstack"]["network"]["rabbit_server_chef_role"]
if node["openstack"]["network"]["rabbit"]["ha"]
  rabbit_hosts = rabbit_servers
end
rabbit_pass = user_password node["openstack"]["network"]["rabbit"]["username"]

identity_endpoint = endpoint "identity-api"
auth_uri = ::URI.decode identity_endpoint.to_s

db_user = node["openstack"]["network"]["db"]["username"]
db_pass = db_password "quantum"
sql_connection = db_uri("network", db_user, db_pass)

api_endpoint = endpoint "network-api"
service_pass = service_password "openstack-network"
service_tenant_name = node["openstack"]["network"]["service_tenant_name"]
service_user = node["openstack"]["network"]["service_user"]

if node["openstack"]["network"]["api"]["bind_interface"].nil?
  bind_address = api_endpoint.host
  bind_port = api_endpoint.port
else
  bind_address = address_for node["openstack"]["network"]["api"]["bind_interface"]
  bind_port = node["openstack"]["network"]["api"]["bind_port"]
end

# retrieve the local interface for tunnels
if node["openstack"]["network"]["openvswitch"]["local_ip_interface"].nil?
  local_ip = node["openstack"]["network"]["openvswitch"]["local_ip"]
else
  local_ip = address_for node["openstack"]["network"]["openvswitch"]["local_ip_interface"]
end

# all recipes include common.rb, and some servers
# may just be running a subset of agents (like l3_agent)
# and not the api server components, so we ignore restart
# failures here as there may be no quantum-server process
service "quantum-server" do
  service_name platform_options["quantum_server_service"]
  supports :status => true, :restart => true
  ignore_failure true

  action :nothing
end

template "/etc/quantum/quantum.conf" do
  source "quantum.conf.erb"
  owner node["openstack"]["network"]["platform"]["user"]
  group node["openstack"]["network"]["platform"]["group"]
  mode   00644
  variables(
    :bind_address => bind_address,
    :bind_port => bind_port,
    :rabbit_hosts => rabbit_hosts,
    :rabbit_pass => rabbit_pass,
    :core_plugin => core_plugin,
    :identity_endpoint => identity_endpoint,
    :service_pass => service_pass
  )

  notifies :restart, "service[quantum-server]", :delayed
end

template "/etc/quantum/api-paste.ini" do
  source "api-paste.ini.erb"
  owner node["openstack"]["network"]["platform"]["user"]
  group node["openstack"]["network"]["platform"]["group"]
  mode   00644
  variables(
    "identity_endpoint" => identity_endpoint,
    "service_pass" => service_pass
  )

  notifies :restart, "service[quantum-server]", :delayed
end

template "/etc/quantum/policy.json" do
  source "policy.json.erb"
  owner node["openstack"]["network"]["platform"]["user"]
  group node["openstack"]["network"]["platform"]["group"]
  mode 00644

  notifies :restart, "service[quantum-server]", :delayed
end

service "quantum-server" do
  service_name platform_options["quantum_server_service"]
  supports :status => true, :restart => true
  action :enable
end

cookbook_file "quantum-ha-tool" do
  source "quantum-ha-tool.py"
  path node["openstack"]["network"]["quantum_ha_cmd"]
  owner "root"
  group "root"
  mode 00755
end

if node["openstack"]["network"]["quantum_ha_cmd_cron"]
  # ensure period checks are offset between multiple l3 agent nodes
  # and assumes splay will remain constant (i.e. based on hostname)
  # Generate a uniformly distributed unique number to sleep.
  checksum   = Digest::MD5.hexdigest(node['fqdn'] || 'unknown-hostname')
  splay = node['chef_client']['splay'].to_i || 3000
  sleep_time = checksum.to_s.hex % splay

  cron "quantum-ha-healthcheck" do
    minute node["openstack"]["network"]["cron_l3_healthcheck"]
    command "sleep #{sleep_time} ; . /root/openrc && #{node["openstack"]["network"]["quantum_ha_cmd"]} --l3-agent-migrate > /dev/null 2>&1"
  end

  cron "quantum-ha-replicate-dhcp" do
    minute node["openstack"]["network"]["cron_replicate_dhcp"]
    command "sleep #{sleep_time} ; . /root/openrc && #{node["openstack"]["network"]["quantum_ha_cmd"]} --replicate-dhcp > /dev/null 2>&1"
  end
end

# the default SUSE initfile uses this sysconfig file to determine the
# quantum plugin to use
template "/etc/sysconfig/quantum" do
  only_if { platform? "suse" }
  source "quantum.sysconfig.erb"
  owner "root"
  group "root"
  mode 00644
  variables(
    :plugin_conf => node["openstack"]["network"]["plugin_conf_map"][driver_name]
  )
  notifies :restart, "service[quantum-server]"
end


# For several plugins, the plugin configuration
# is required by both the quantum-server and
# ancillary services that may be on different
# physical servers like the l3 agent, so we assume
# the plugin configuration is a "common" file

template_file = nil

case main_plugin
when "bigswitch"

  template_file =  "/etc/quantum/plugins/bigswitch/restproxy.ini"
  template "/etc/quantum/plugins/bigswitch/restproxy.ini" do
    source "plugins/bigswitch/restproxy.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

when "brocade"

  template_file = "/etc/quantum/plugins/brocade/brocade.ini"
  template "/etc/quantum/plugins/brocade/brocade.ini" do
    source "plugins/brocade/brocade.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

when "cisco"

  template_file = "/etc/quantum/plugins/cisco/cisco_plugins.ini"
  template "/etc/quantum/plugins/cisco/cisco_plugins.ini" do
    source "plugins/cisco/cisco_plugins.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

when "hyperv"

  template_file = "/etc/quantum/plugins/hyperv/hyperv_quantum_plugin.ini.erb"
  template "/etc/quantum/plugins/hyperv/hyperv_quantum_plugin.ini.erb" do
    source "plugins/hyperv/hyperv_quantum_plugin.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

when "linuxbridge"

  template_file = "/etc/quantum/plugins/linuxbridge/linuxbridge_conf.ini"
  template "/etc/quantum/plugins/linuxbridge/linuxbridge_conf.ini" do
    source "plugins/linuxbridge/linuxbridge_conf.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

when "midonet"

  template_file = "/etc/quantum/plugins/metaplugin/metaplugin.ini"
  template "/etc/quantum/plugins/metaplugin/metaplugin.ini" do
    source "plugins/metaplugin/metaplugin.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

when "nec"

  template_file = "/etc/quantum/plugins/nec/nec.ini"
  template "/etc/quantum/plugins/nec/nec.ini" do
    source "plugins/nec/nec.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

when "nicira"

  template_file = "/etc/quantum/plugins/nicira/nvp.ini"
  template "/etc/quantum/plugins/nicira/nvp.ini" do
    source "plugins/nicira/nvp.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

when "openvswitch"

  template_file = "/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini"

  service "quantum-plugin-openvswitch-agent" do
    service_name platform_options["quantum_openvswitch_agent_service"]
    action :nothing
  end

  template "/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini" do
    source "plugins/openvswitch/ovs_quantum_plugin.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection,
      :local_ip => local_ip
    )
    notifies :restart, "service[quantum-server]", :delayed
    if node.run_list.expand(node.chef_environment).recipes.include?("openstack-network::openvswitch")
      notifies :restart, "service[quantum-plugin-openvswitch-agent]", :delayed
    end
  end


when "plumgrid"

  template_file = "/etc/quantum/plugins/plumgrid/plumgrid.ini"
  template "/etc/quantum/plugins/plumgrid/plumgrid.ini" do
    source "plugins/plumgrid/plumgrid.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

when "ryu"

  template_file = "/etc/quantum/plugins/ryu/ryu.ini"
  template "/etc/quantum/plugins/ryu/ryu.ini" do
    source "plugins/ryu/ryu.ini.erb"
    owner node["openstack"]["network"]["platform"]["user"]
    group node["openstack"]["network"]["platform"]["group"]
    mode 00644
    variables(
      :sql_connection => sql_connection
    )

    notifies :restart, "service[quantum-server]", :delayed
  end

end


template "/etc/default/quantum-server" do
  source "quantum-server.erb"
  owner "root"
  group "root"
  mode 00644
    variables(
      :plugin_config => template_file
    )
  only_if { platform?(%w{ubuntu debian}) }
end

