[ソースコードで体感するネットワークの仕組み](https://www.amazon.co.jp/dp/4774197440) の写経

# remote development

```sh
## 途中で `umount /mnt` が失敗する
vagrant up

## 仮想マシン内のモジュールを最新にして reload すると vagrant-vbguest plugin がディレクトリ共有に必要な設定を行ってくれる
vagrant provision
vagrant reload

## 仮想マシンにアクセス
vagrant ssh

##  ~/.ssh/config に貼り付けて ssh する
vagrant ssh-config 
```
