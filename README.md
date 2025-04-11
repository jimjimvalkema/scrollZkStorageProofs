# scrollZkStorageProofs
install node version 22 or higher

## deprecation notice
Scroll is going to switch to a keccak based MPT state trie in the [euclid upgrade](https://x.com/shenhaichen/status/1910527255920730363). But this repo is build around the old state model.

## install js
```
yarn install
```

## install nargo (noir)
```
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash;
source ~/.bashrc;
noirup;
```

## install nargo backend
```shell
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash;
source ~/.bashrc;
 bbup --version 0.41.0;
```

## test noir
```
cd circuits/test;
nargo test --show-output
```


## usage 
run storage proof decoder js
```shell
node  ./scripts/fetchStorageProof.js --mappingMode --contractAddress=0x5300000000000000000000000000000000000004 --key=0xf1B42cc7c1609445620dE4352CD7e58353C3FA74 --slot=0x00 --keyType=address --decode
```
