openvpn_generator
------------------------
Python-native deterministic generator for OpenVPN TLS Crypt v2 Keys.

In some experiments I've been doing, I have a need to generate an OpenVPN Server/Client key independent of the OpenVPN binary. This code attempts to generate keys that will match and work, and generate the same keys if given the same seeds.

Not guaranteed to be secure for any production use-case, actually work, or to be kept current as OpenVPN makes changes. Just releasing the code in case anyone else is interested.


### Quick start

```shell
$ ./gen_ovpn_keys.py  --server-seed 'test123' --client-seed 'test123'
Generating TLS-crypt-v2 keys...
Server key written to: tls-crypt-v2-server.key
Client key written to: tls-crypt-v2-client.key

Keys generated successfully!

To use these keys with OpenVPN:
  Server config: tls-crypt-v2 tls-crypt-v2-server.key
  Client config: tls-crypt-v2 tls-crypt-v2-client.key
$ 
```

### Usage
```shell
$ ./gen_ovpn_keys.py  --server-seed 'test123' --client-seed 'test123' -h
usage: gen_ovpn_keys.py [-h] --server-seed SERVER_SEED --client-seed CLIENT_SEED [--server-output SERVER_OUTPUT] [--client-output CLIENT_OUTPUT] [--metadata METADATA] [--test] [--json]

Generate deterministic OpenVPN TLS-crypt-v2 keys from seed data

options:
  -h, --help            show this help message and exit
  --server-seed SERVER_SEED
                        Seed data for server key (hex string or text)
  --client-seed CLIENT_SEED
                        Seed data for client key (hex string or text)
  --server-output SERVER_OUTPUT
                        Output file for server key (default: tls-crypt-v2-server.key)
  --client-output CLIENT_OUTPUT
                        Output file for client key (default: tls-crypt-v2-client.key)
  --metadata METADATA   Custom metadata to include in client key (hex string)
  --test                Test generated keys with OpenVPN (requires openvpn binary)
  --json                Output keys as JSON to stdout instead of writing to files
$ 
```

### License
MIT
