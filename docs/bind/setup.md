# Setup minimal DNS server for testbench

This documents describes how to set up a minimal DNS server on a host running BDC.  
The outline is as follows

* Use Ubuntu 20.04LTS as OS
* Setup DNS with BIND9
* Only respond to requests for a single FQDN and corresponding IP address
* Not in Production

## Install and setup

### Properties

| Property | Description |
|----------|-------------|
| CLINET FQDN | Client FQDN. Same as `<CLIENT FQDN WITHOUT DOMAIN>.<DOMAIN>` |
| CLIENT FQDN WITHOUT DOMAIN | Client FQDN minus DOMAIN |
| DOMAIN | Client DOMAIN |
| CLIENT IP ADDRESS | Client IP Address |
| NAME SERVER FQDN | NameServer(Host) FQDN |
| NAME SERVER IP | NameServer(Host) IP Address|

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

Check the configuration by bellow command line tools

```bash
/usr/sbin/named-checkconf
/usr/sbin/named-checkzone <DOMAIN> /var/cache/bind/<DOMAIN>.zone
```

If there is no problem, then enable `named` service.

```bash
sudo systemctl start named
```

The above configuration only allows DNS A record queries from the DNS server itself or from the client server.
It is OK if both servers confirm the following

```bash
# Check inside the DNS server
$ dig @localhost <CLIENT FQDN>

# Check inside the client server
$ dig @<NAME SERVER IP> <CLIENT FQDN>
```
