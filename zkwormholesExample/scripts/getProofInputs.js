// const { ethers, N } = require("ethers");
// const { poseidon1 } = require("poseidon-lite");
import { poseidon1 } from "poseidon-lite";
import { ethers } from "ethers";
import * as fs from 'node:fs/promises';
import { getHashPathFromProof } from "../../scripts/decodeScrollProof.js"
import { createStoragePositionMapping, getBlockHeaderRlp } from "../../scripts/getScrollProof.js"
import { ZkTrieNode, NodeTypes, leafTypes } from "../../scripts/types/ZkTrieNode.js";
import argParser from 'args-parser'


const PROVER_TOML = 'zkwormholesExample/circuits/smolProver/Prover.toml'

const MAX_HASH_PATH_SIZE = 32;//248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
const MAX_RLP_SIZE = 650//1000; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
// TODO actually find out what the largest value could be 

const abi = [
    "function balanceOf(address) view returns (uint)"
];



async function getProof(contractAddress, storageKey, blockNumber, provider) {
    const blockNumberHex = "0x" + blockNumber.toString(16)

    const params = [contractAddress, [storageKey], blockNumberHex,]
    const proof = await provider.send('eth_getProof', params)
    return proof
}

function paddArray(arr, len = 32, filler = 0, infront = true) {
    if (infront) {
        return [...Array(len - arr.length).fill(filler), ...arr]

    } else {
        return [...arr, ...Array(len - arr.length).fill(filler)]
    }


}

function asPaddedArray(value, len = 32, infront = true) {
    const valueArr = [...ethers.toBeArray(value)]
    return paddArray(valueArr, len, 0, infront)
}

/**
 
 * @typedef hashPaths
 * @property {proofData} account 
 * @property {proofData} storage 

 * @typedef proofData
 * @property {ethers.BytesLike[]} hashPath from leaf-hash-sybling to root-child
 * @property {number[]} nodeTypes from leaf-hash-sybling to root-child
 * @property {ZkTrieNode} leafNode used for the leafHash and nodeKey/hashPathBools in proving
 * 

 * @param {*} BlockHash 
 * @param {*} remintAddress 
 * @param {*} secret 
 * @param {*} burnedTokenBalance 
 * @param {*} contractBalance 
 * @param {*} headerRlp 
 * @param {*} nonce_codesize_0 
 * @param {hashPaths} hashPaths 
 * @returns 
 */
export async function formatToTomlProver(block,headerRlp, remintAddress, secret, burnedTokenBalance, contractBalance, hashPaths, maxHashPathLen=maxHashPathLen,maxRlpLen=maxRlpLen ) {
    //const headerRlp = await getBlockHeaderRlp(Number(block.number), provider)
    return `block_hash = [${[...ethers.toBeArray(block.hash)].map((x)=>`"${x}"`)}] 
remint_address = "${remintAddress}"
secret = "${ethers.toBeHex(secret)}"
user_balance =  [${asPaddedArray(burnedTokenBalance, 32).map((x)=>`"${x}"`)}]

[storage_proof_data]
contract_balance = "${contractBalance}"
header_rlp =  [${[...ethers.toBeArray(ethers.zeroPadBytes(headerRlp,maxRlpLen))].map((x)=>`"${x}"`)}]
header_rlp_len = "${ethers.toBeArray(headerRlp).length}"
nonce_codesize_0 = "${hashPaths.account.leafNode.valuePreimage[0]}"

[storage_proof_data.hash_paths.account_proof]
hash_path = [${paddArray(hashPaths.account.hashPath, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
leaf_type = "${hashPaths.account.leafNode.type}"
node_types = [${paddArray(hashPaths.account.nodeTypes, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
real_hash_path_len = "${hashPaths.account.hashPath.length}"` 
+
`\nhash_path_bools = [${paddArray(hashPaths.account.leafNode.hashPathBools.slice(0,hashPaths.account.hashPath.length).reverse(), maxHashPathLen, 0,false).map((x)=>`"${Number(x)}"`)}]`
+
`\n
[storage_proof_data.hash_paths.storage_proof]
hash_path = [${paddArray(hashPaths.storage.hashPath, maxHashPathLen, 0,false).map((x)=>`"${x}"`)}]
leaf_type = "${hashPaths.storage.leafNode.type}"
node_types = [${paddArray(hashPaths.storage.nodeTypes, maxHashPathLen,  0,false).map((x)=>`"${x}"`)}]
real_hash_path_len = "${hashPaths.storage.hashPath.length}"`
+
`\nhash_path_bools =  [${paddArray(hashPaths.storage.leafNode.hashPathBools.slice(0,hashPaths.storage.hashPath.length).reverse(), maxHashPathLen, false,false).map((x)=>`"${Number(x)}"`)}]`
}

export async function getProofData(contractAddress = "0x29d801Af49F0D88b6aF01F4A1BD11846f0c96672", burnAddress, blockNumber = 5093419, provider = provider) {



    const tokenContract = new ethers.Contract(contractAddress, abi, provider)

    const burnedTokenBalance = await tokenContract.balanceOf(burnAddress)
    console.log({ burnedTokenBalance })
    //slot pos for balances of weth contract
    const mappingSlot = "0x00"
    //get possition of mapping value keccak(lookUpAddress, mappingPosition ) 
    const storageKey = createStoragePositionMapping(burnAddress, "address", mappingSlot)
    const proof = await getProof(contractAddress, storageKey, blockNumber, provider)


    const hashPaths = {
        "account": getHashPathFromProof(proof.accountProof),
        "storage": getHashPathFromProof(proof.storageProof[0].proof)
    }


    const block = await provider.getBlock(blockNumber)
    const contractBalance = await provider.getBalance(contractAddress)
    return { block, burnedTokenBalance, contractBalance, hashPaths, provider }
}

/**
 * 
 * @param {ethers.HexString} input 
 * @param {Number} bytes 
 * @returns 
 */
function Bytes(input, len) {
    const regEx = new RegExp(`.{1,${2 * len}}`, "g")
    return input.slice(2).match(regEx).map((x) => "0x" + x)

}
/**
 * 
 * @param {*} contractAddress 
 * @param {*} blockNumber 
 * @param {*} remintAddress 
 * @param {*} secret 
 * @param {*} provider 
 * @returns 
 */
export async function getProofInputs(contractAddress, blockNumber, remintAddress, secret, provider) {
    const burnAddress = ethers.hexlify(ethers.toBeArray(poseidon1([secret])).slice(0,20))
    const {block,burnedTokenBalance, contractBalance , hashPaths}  = await getProofData(contractAddress,burnAddress,blockNumber, provider)
    const headerRlp = await getBlockHeaderRlp(Number(blockNumber), provider)
    return {
        blockData:{block, headerRlp},
        burnAddress,
        noirJsInputs: {
            storage_proof_data: {
                hash_paths: {
                    account_proof: {
                        hash_path: paddArray(hashPaths.account.hashPath, MAX_HASH_PATH_SIZE, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                        leaf_type: (ethers.toBeHex(hashPaths.account.leafNode.type)),
                        node_types: paddArray(hashPaths.account.nodeTypes, MAX_HASH_PATH_SIZE, 0, false),
                        real_hash_path_len: (ethers.toBeHex(hashPaths.account.hashPath.length)),
                        hash_path_bools: paddArray(hashPaths.account.leafNode.hashPathBools.slice(0, hashPaths.account.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false, false),
                    },
                    storage_proof: {
                        hash_path: paddArray(hashPaths.storage.hashPath, MAX_HASH_PATH_SIZE, ethers.zeroPadBytes("0x00", 32), false).map((x) => (x)),
                        leaf_type: (ethers.toBeHex(hashPaths.storage.leafNode.type)),
                        node_types: paddArray(hashPaths.storage.nodeTypes, MAX_HASH_PATH_SIZE, 0, false),
                        real_hash_path_len: (ethers.toBeHex(hashPaths.storage.hashPath.length)),
                        hash_path_bools: paddArray(hashPaths.storage.leafNode.hashPathBools.slice(0, hashPaths.storage.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false, false),

                    },
                },
                contract_balance: (ethers.toBeHex(contractBalance)),
                header_rlp: [...ethers.toBeArray(ethers.zeroPadBytes(headerRlp, MAX_RLP_SIZE))].map((x) => ethers.toBeHex(x)),
                header_rlp_len: ethers.toBeArray(headerRlp).length,
                nonce_codesize_0: (hashPaths.account.leafNode.valuePreimage[0]),
            },
            secret: (ethers.toBeHex(secret)),
            remint_address: (remintAddress),
            user_balance: asPaddedArray(burnedTokenBalance, 32).map((x) => ethers.toBeHex(x)),
            block_hash: [...ethers.toBeArray(block.hash)].map((x) => ethers.toBeHex(x))
        }
    }
}


export async function formatTest(proofInputs,block,headerRlp, remintAddress, secret,burnedTokenBalance, contractBalance , hashPaths) {
    const proofInputs = getProofInputs()
    // const headerRlp = await getBlockHeaderRlp(Number(block.number), provider)
    return`
#[test]
fn test_main() {
    let storage_proof_data = Storage_proof_data {
        hash_paths :Hash_paths_state_proof{
                account_proof: Hash_path_proof {
                hash_path:  [${paddArray(hashPaths.account.hashPath, MAX_HASH_PATH_SIZE, 0,false)}],
                leaf_type: ${hashPaths.account.leafNode.type},
                node_types: [${paddArray(hashPaths.account.nodeTypes, MAX_HASH_PATH_SIZE, 0,false)}],
                real_hash_path_len: ${hashPaths.account.hashPath.length},`
                +
                `
                hash_path_bools: [${paddArray(hashPaths.account.leafNode.hashPathBools.slice(0,hashPaths.account.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false,false).map((x)=>`${x}`)}]`
                +
                `
            },
            storage_proof: Hash_path_proof {
                hash_path: [${paddArray(hashPaths.storage.hashPath, MAX_HASH_PATH_SIZE, 0,false)}],
                leaf_type: ${hashPaths.storage.leafNode.type},
                node_types: [${paddArray(hashPaths.storage.nodeTypes, MAX_HASH_PATH_SIZE,  0,false)}],
                real_hash_path_len: ${hashPaths.storage.hashPath.length},`
                +
                `
                hash_path_bools: [${paddArray(hashPaths.storage.leafNode.hashPathBools.slice(0,hashPaths.storage.hashPath.length).reverse(), MAX_HASH_PATH_SIZE, false,false).map((x)=>`${x}`)}]`
                +
                `
            },
        },
            contract_balance: ${contractBalance},
            header_rlp:[${[...ethers.toBeArray(ethers.zeroPadBytes(headerRlp,MAX_RLP_SIZE))]}],
            header_rlp_len:${ethers.toBeArray(headerRlp).length},
            nonce_codesize_0:${hashPaths.account.leafNode.valuePreimage[0]},
        };


    let secret = ${secret};

    let remint_address = ${remintAddress};
    let user_balance = [${asPaddedArray(burnedTokenBalance, 32)}];
    let block_hash =  [${[...ethers.toBeArray(block.hash)]}];
}`
}

async function setDefaults(args) {
    const defaults = {
        contract: "0xDb9Fb1e8d6A0b9C0072D3E88f8330ec9Cc62E21f",
        recipient: "0x93211e420c8F552a0e4836f84892a0D4eb5D6D54",
        secret: 123,
        rpc:  "https://scroll-sepolia.drpc.org",
        blocknumber: "latest", 
    }
    for (const defaultParam in defaults) {
        if (args[defaultParam] === undefined) {
            console.log(`"--${defaultParam}= " not set defaulting to ${defaults[defaultParam]}`)
            args[defaultParam] = defaults[defaultParam]
        }
    }
    return args
}

async function main() {
    let args = argParser(process.argv)
    if (Object.keys(args).length) {
        args = await setDefaults(args)
        const contractAddress = args["contract"]
        const remintAddress = args["recipient"]
        const secret = args["secret"]
        const providerUrl = args["rpc"]
        const provider = new ethers.JsonRpcProvider(providerUrl) 
        const blockNumber =  await provider.getBlockNumber(args["blocknumber"])
        const proofInputs = await getProofInputs(contractAddress,blockNumber,remintAddress,secret,provider)
        console.log({proofInputs})
        console.log(formatTest(proofInputs))


    }

}

main()