# scrollZkStorageProofs
install node version 22 or higher


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