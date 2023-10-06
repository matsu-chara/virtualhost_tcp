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
      yum -y update
    SHELL
  end

  config.vm.define :node2 do |node|
    node.vm.box = "bento/centos-7"
    node.vm.network :private_network, ip:"192.168.33.12"
    node.vm.provision "shell", inline: <<-SHELL
      yum -y update
    SHELL
  end
end
