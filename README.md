# Adapting the filecoin C2 prover for Gevulot


## The Prover

### Download the proof parameters file
The proving algorithms rely on a large binary parameter file known as the Groth parameters. This file is stored in a cache directory, typically /var/tmp/filecoin-proof-parameters.

The `paramfetch` program fetches params to local cache directory from IPFS gateway. 
```
cargo run --release --bin paramfetch -- -z 32GiB
```

#### Speed up proof parameter download for china users
export IPFS_GATEWAY=https://proof-parameters.s3.cn-south-1.jdcloud-oss.com/ipfs/


### Build Prover image
```
cargo build --bin c2-prover
```
### Deploy prover
```
gevulot-cli deploy --name gevulot-fil-c2 --prover ~/.ops/images/c2-prover --verifier ~/.ops/images/c2-verifier
```

## [Damocles](https://github.com/ipfs-force-community/damocles) integration
```
cargo run --release --bin gevulot-fil-damocles-plugin
```

Configure Damocles
```toml
[[processors.sealing_daemons]]
bin = "/path/to/gevulot-fil-damocles-plugin"
args = ["--fileserver-path", "/var/tmp/gevulot-fil-storage", "fileserver", "--listen", "0.0.0.0:31313"]
stable_wait = "10s"

[[processors.c2]]
bin="/path/to/gevulot-fil-damocles-plugin"
args = ["--rpc-url", "http://127.0.0.1:9944", "--fileserver-path", "/var/tmp/gevulot-fil-storage", "--fileserver-base-url", "http://127.0.0.1:31313/static"]
envs = {}
```
