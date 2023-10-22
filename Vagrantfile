# -*- mode: ruby -*-
# vi: set ft=ruby :

def install_plugin(plugin)
  system "vagrant plugin install #{plugin}" unless Vagrant.has_plugin? plugin
end

# 必要なプラグイン
install_plugin('vagrant-vbguest')

Vagrant.configure("2") do |config|
  config.vm.define :node1 do |node|
    node.vm.box = "bento/centos-7"
    node.vm.network :private_network, ip:"192.168.33.11"
    node.vm.provision "shell", inline: <<-SHELL
      yum update -y
    SHELL
  end

  config.vm.define :node2 do |node|
    node.vm.box = "bento/centos-7"
    node.vm.network :private_network, ip:"192.168.33.12"
    node.vm.provision "shell", inline: <<-SHELL
      yum update -y
      yum install -y dhcp nc
      sudo cat > /etc/dhcp/dhcpd.conf <<EOS
#
# DHCP Server Configuration file.
#   see /usr/share/doc/dhcp*/dhcpd.conf.example
#   see dhcpd.conf(5) man page
#
subnet 192.168.33.0 netmask 255.255.255.0 {
  range 192.168.33.100 192.168.33.200;
  option subnet-mask 255.255.255.0;
  option routers 192.168.33.12;
  option broadcast-address 192.168.33.255;
  default-lease-time 900;
  max-lease-time 3600;
}
EOS
      systemctl start dhcpd
      systemctl enable dhcpd
    SHELL
  end
end
