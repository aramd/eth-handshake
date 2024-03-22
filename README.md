# p2p eth-handshake

## Description

**p2p-eth-handshake** is a proof of concept implementation of the Ethereum handshake protocol (RLPx). RLPx is the network layer for the Ethereum protocol, providing secure peer-to-peer communication.

This implementation follows the specifications outlined in the [RLPx documentation](https://github.com/ethereum/devp2p/blob/master/rlpx.md), allowing nodes to establish connections and exchange messages securely over the Ethereum network.

The project is divided into two components: a library that encompasses the data structures pertaining to the protocol, and a CLI responsible for executing the handshake process.

## Usage

```
Usage: eth-handshake <ENODE>

Arguments:
  <ENODE> Ethereum node in the Ethereum peer-to-peer network.
```

Enode has enode://<node_id>@<ip>:<post> format and you can get from [ethernodes.org](https://ethernodes.org/node/c32e699c07bb16383dab918d7650a8644b334bbf2e900c99e2542c4b60e93f72087281eb06302f7142a274e769e86692bf82f48f9e3721f054549c69f9b51177) site.

## Examples

```
> cargo run enode://2b8793c4bba9dadcd0dcbe6cda21ff835e4a2e4c3ef4b5330e6c3a2798080f570e643665839e52518fbaee83a37042b22f73101ee279d60a3d763cebc67eaa95@34.94.54.138:30303
Finished dev [unoptimized + debuginfo] target(s) in 0.45s
Running `target/debug/eth-handshake 'enode://2b8793c4bba9dadcd0dcbe6cda21ff835e4a2e4c3ef4b5330e6c3a2798080f570e643665839e52518fbaee83a37042b22f73101ee279d60a3d763cebc67eaa95@34.94.54.138:30303'`
2024-03-22T18:49:52.503760Z  INFO eth_handshake::client: Connecting to 34.94.54.138:30303
2024-03-22T18:49:52.711002Z  INFO eth_handshake::client: Initiating handshake protocol
2024-03-22T18:49:52.713408Z  INFO eth_handshake::client: Auth message is sent to target node
2024-03-22T18:49:53.132182Z  INFO eth_handshake::client: Ack message is received from target node
2024-03-22T18:49:53.132689Z  INFO eth_handshake::client: Hello message is sent to target node
2024-03-22T18:49:53.133386Z  INFO eth_handshake::client: Hello message is received from target node: Hello { version: 5, client: "Nethermind/v1.25.4+20b10b35/linux-x64/dotnet8.0.2", id: PublicKey(570f0898273a6c0e33b5f43e4c2e4a5e83ff21da6cbedcd0dcdaa9bbc493872b95aa7ec6eb3c763d0ad679e21e10732fb24270a383eeba8f51529e836536640e) }
2024-03-22T18:49:53.133455Z  INFO eth_handshake::client: Handshake is complete!!!
```

```
./eth-handshake enode://98742cfaf2dc6f28214adc3da69c094ca76551ade4f6d1de7339be4bafd250c2534a4bee3d946495c43fd0e134e386fe8596bddff6d33c689c9591a1b07bf616@46.125.46.214:30308         
2024-03-22T18:54:10.945798Z  INFO eth_handshake: args Args { node_id: "98742cfaf2dc6f28214adc3da69c094ca76551ade4f6d1de7339be4bafd250c2534a4bee3d946495c43fd0e134e386fe8596bddff6d33c689c9591a1b07bf616", ip: 46.125.46.214, port: 30308 }
2024-03-22T18:54:10.945880Z  INFO eth_handshake::client: Connecting to 46.125.46.214:30308
2024-03-22T18:54:11.797060Z  INFO eth_handshake::client: Initiating handshake protocol
2024-03-22T18:54:11.798839Z  INFO eth_handshake::client: Auth message is sent to target node
2024-03-22T18:54:12.322449Z  INFO eth_handshake::client: Ack message is received from target node
2024-03-22T18:54:12.323008Z  INFO eth_handshake::client: Hello message is sent to target node
2024-03-22T18:54:12.811352Z  INFO eth_handshake::client: Hello message is received from target node: Hello { version: 5, client: "besu/v24.3.0/linux-x86_64/openjdk-java-17", id: PublicKey(c250d2af4bbe3973ded1f6e4ad5165a74c099ca63ddc4a21286fdcf2fa2c749816f67bb0a191959c683cd3f6dfbd9685fe86e334e1d03fc49564943dee4b4a53) }
2024-03-22T18:54:12.811414Z  INFO eth_handshake::client: Handshake is complete!!!
```

It is possible to see some DEBUG information. You just need to run debug log level `RUST_LOG=DEBUG`

```
RUST_LOG=DEBUG ./eth-handshake enode://98742cfaf2dc6f28214adc3da69c094ca76551ade4f6d1de7339be4bafd250c2534a4bee3d946495c43fd0e134e386fe8596bddff6d33c689c9591a1b07bf616@46.125.46.214:30308
```

## Note

This code tests only against `Nethermind`, `besu` and `reth` clients. 






