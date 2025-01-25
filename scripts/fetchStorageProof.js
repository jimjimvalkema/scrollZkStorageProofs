#!/usr/bin/env node
'use strict';

import { ArgumentParser } from 'argparse';
import { ethers, assert } from 'ethers';
import { decodeProof , hashStorageKeyMapping, getBlockHeaderProof} from "./decodeScrollProof.js"


export async function getProof({ provider, blockNumber, contractAddress, storageKey, decode=true }) {
  storageKey = ethers.zeroPadValue(storageKey, 32)
  const blockNumberHex = "0x" + blockNumber.toString(16)

  const params = [contractAddress, [storageKey], blockNumberHex,]
  const proof = await provider.send('eth_getProof', params)
  const {rlp, byteNibbleOffsets} = await getBlockHeaderProof({blockNumber, provider})
  const headerProof = {rlp, stateRootOffset: byteNibbleOffsets.stateRoot.offset/2}

  if (decode) {
    const decodedProof = await decodeProof({proof: proof.proof,provider,blockNumber})
    return decodedProof
  } else {
    return {proof, headerProof, blockNumber}
  }
}


export async function getProofOfMapping({ provider, blockNumber, contractAddress, slot, key, keyType , decode=true}) {
  const storageKey = hashStorageKeyMapping({ key, keyType, slot })
  const proof = await getProof({ provider, blockNumber, contractAddress, storageKey, decode:false })
  if (decode) {
    const decodedProof = await decodeProof({proof: proof.proof,provider,blockNumber})
    return decodedProof
  } else {
    return proof
  }
}

export function verifyDecodedProof({proof}) {

}




async function main() {
  const mappingUsageExample = 'node ./fetchStorageProof.js --mappingMode --contractAddress=0x5300000000000000000000000000000000000004 --key=0xf1B42cc7c1609445620dE4352CD7e58353C3FA74 --slot=0x00 --keyType=address'
  const normalSlotExample = 'node ./fetchStorageProof.js --contractAddress=0x5300000000000000000000000000000000000004 --slot=0x03'
  const parser = new ArgumentParser({
    description: 'Argparse example',
    usage: `\n mapping mode (gets weth balance of jimjim.jimjim.eth): ${mappingUsageExample}\n normal slot (gets weth name): ${normalSlotExample}`
  });

  // optional
  parser.add_argument('-p', '--provider', { help: 'Provider url. Default uis mainnet. ex: mainnet: --provider=https://rpc.scroll.io or sepolia: --provider=https://sepolia-rpc.scroll.io', required: false, default: "https://rpc.scroll.io" });
  parser.add_argument('-b', '--blockNumber', { help: 'From which blocknumber to fetch the proof. Default is latest. ex --blocknumber=6969', required: false, type: 'int' });
  parser.add_argument('-d', '--decode', { action: 'store_true', help: 'Returns the decoded proof instead', required: false },)

  // required for mapping lookup
  parser.add_argument('-m', '--mappingMode', { action: 'store_true', help: 'Alternative mode for mapping values, hashes the key and slot for you to get a proof for a value in a mapping', required: false },)
  parser.add_argument('-k', '--key', { help: 'Used in mappingMode, the key in a mapping (ex a address in a _balances mapping). ex: --key=0xf1B42cc7c1609445620dE4352CD7e58353C3FA74', required: false, type: 'str' });
  parser.add_argument('-t', '--keyType', { help: 'ex --blocknumber=6969', required: false, type: 'str' });

  // always required
  parser.add_argument('-c', '--contractAddress', { help: 'The contract to get proofs for ex: --contractAddress=0x5300000000000000000000000000000000000004', required: true, type: 'str' });
  parser.add_argument('-s', '--slot', { help: 'The slot number. ex --slot=0 or slot=0x00', required: true, type: 'str' });

  const requiredMappingArgs = ["key", "keyType"]
  const args = parser.parse_args() 
  const provider = new ethers.JsonRpcProvider(args.provider);

  if (args.blockNumber === undefined) {
    args["blockNumber"] = await provider.getBlockNumber("latest")
  }

  if (args.mappingMode == true) {
    const missingArgs = requiredMappingArgs.filter((a) => args[a] === undefined)
    if (missingArgs.length) {
      console.error(`\nmissing args (${missingArgs}) for a mapping lookup. Remove the --mappingMode flag if you want a proof for a normal slot \n`)
      parser.print_help()
      process.exit(1);
    } else {
      const proof = await getProofOfMapping({ provider, blockNumber: args.blockNumber, contractAddress: args.contractAddress, slot: args.slot, key: args.key, keyType: args.keyType , decode:args.decode})
      process.stdout.write(JSON.stringify(proof, null, 2) + '\n');
      process.exit(0);

    }
  } else {
    const extraArgs = requiredMappingArgs.filter((a) => args[a] !== undefined)
    if (extraArgs.length) {
      console.error(`\nfound arguments (${extraArgs}) for a mapping lookup but the --mappingMode flag is not set \n`)
      parser.print_help()
      process.exit(1);
    } else {
      const proof = await getProof({ provider, blockNumber: args.blockNumber, contractAddress: args.contractAddress, storageKey: args.slot, decode:args.decode })
      process.stdout.write(JSON.stringify(proof, null, 2) + '\n');
      process.exit(0);
    }
  }
}

await main()