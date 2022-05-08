# Setup minimal DNS server for testbench

本稿では`BDC`を動作させるホスト上に最小構成のDNSサーバのセットアップを実施する方法を記載する
概略は以下の通り

* OSはUbuntu 20.04LTSを利用
* Bind9でDNSを構築
* 単一のFQDNとそれに対応するIPアドレスについてのリクエストにのみ返答する
* Not in Production

## Install and setup

### Properties

| Property | Description |
|----------|-------------|
| CLINET FQDN | クライアントのFQDN. <CLIENT FQDN WITHOUT DOMAIN>.<DOMAIN>と同一 |
| CLIENT FQDN WITHOUT DOMAIN | クライアントのFQDNからDOMAINを抜いたもの |
| DOMAIN | クライアントのDOMAIN |
| CLIENT IP ADDRESS | クライアントのIPアドレス |
| NAME SERVER FQDN | ネームサーバのFQDN |
| NAME SERVER IP | ネームサーバのIPアドレス |

### Setup

```bash
sudo apt-get install -y bind9 bind9utils


sudo tee -a /etc/bind/named.conf <<EOF
include "/etc/bind/named.conf.internal-zones";
EOF

sudo tee /etc/bind/named.conf.options <<EOF
options {
        directory "/var/cache/bind";
	allow-query {
		localhost;
	    	<CLIENT IP ADDRESS>/32;
	};
	recursion no;
        dnssec-validation auto;

        listen-on-v6 { any; };
};
EOF

sudo tee -a /etc/bind/named.conf.internal-zones <<EOF
zone "<DOMAIN>" IN {
	type master;
	file "<DOMAIN>.zone";
	allow-update { none; };
};
EOF

sudo sed -i 's|OPTIONS.*|OPTIONS="-u bind -4"|' /etc/default/named

sudo tee /var/cache/bind/<DOMAIN>.zone <<EOF
$TTL      86400
@         IN       SOA     <DOMAIN>.  root.test.local.(
                                        2020020501 ; Serial
                                        28800      ; Refresh
                                        14400      ; Retry
                                        3600000    ; Expire
                                        86400 )    ; Minimum
            IN NS <NAME SERVER FQDN>.
	    IN A  <NAME SERVER IP>
<CLIENT FQDN WITHOUT DOMAIN>   IN A <CLIENT IP ADDRESS>
EOF
```

### Varidation and Run

以下のコマンドで設定項目に問題がないかを確認する

```bash
/usr/sbin/named-checkconf
/usr/sbin/named-checkzone <DOMAIN> /var/cache/bind/<DOMAIN>.zone
```

問題ない場合は、サービスを有効化する。

```bash
sudo systemctl start named
```

上記の設定では、DNSサーバ自体、もしくはクライアントサーバからのDNS Aレコード問い合わせのみ許可している
両方で以下のように確認できればOK

```bash
# DNSサーバ内部で確認
$ dig @localhost <CLIENT FQDN>

# クライアントサーバ内部で確認
$ dig @<NAME SERVER IP> <CLIENT FQDN>
```
