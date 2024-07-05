import { encryptKeystoreJson, ethers } from "ethers";
import { buildPoseidon, buildPoseidonWasm, buildPoseidonOpt } from "circomlibjs";
import { 
    poseidon1,poseidon2,poseidon3,poseidon4,poseidon5,poseidon6,poseidon7,poseidon8,poseidon9,poseidon10,poseidon11,poseidon12,poseidon13,poseidon14,poseidon15,poseidon16 
} from "poseidon-lite";
import { getCurveFromName } from "ffjavascript";

import * as fs from 'node:fs/promises';
import * as snarkjs from "snarkjs"


//----some stuff so i can test things in the browser console (i prefer it)
let windowIsEmpty = true
// Check if the environment is Node.js
if (typeof process === "object" &&
    typeof require === "function") {
    windowIsEmpty = true;
} else {
    if (typeof window === "object") {
        // Check if the environment is a Browser
        windowIsEmpty = false;
        window.ethers = ethers
        window.getCurveFromName = getCurveFromName;
        window.buildPoseidon = buildPoseidon
        window.poseidon1 = poseidon1
        window.poseidon2 = poseidon2
        window.poseidon3 = poseidon3
        window.getProof = getProof
        //window.NewNodeFromBytes = NewNodeFromBytes
        window.DecodeSMTProof = DecodeSMTProof
        const PROVIDERURL = "https://scroll.drpc.org"//"https://scroll-sepolia.drpc.org"
        const provider = new ethers.JsonRpcProvider(PROVIDERURL)
        window.provider = provider
        window.getStorageAt = getStorageAt
    }

}

const magicSMTBytes = new TextEncoder().encode("THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI")//[]byte("THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI")

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_proof.go#L19
// DecodeProof try to decode a node bytes, return can be nil for any non-node data (magic code)
export function DecodeSMTProof(bytes) {

	if (ethers.hexlify(bytes) === ethers.hexlify(magicSMTBytes)) {// a1.every((c,i)=>magicSMTBytes[i] === bytes[i])    ) {
		//skip magic bytes node
        console.warn("skipping magicSMTBytes")
		return 0
	}

	return NewNodeFromBytes(bytes)
}





export function formatProofNodes(proof) {
    let trie_proof = []
    for (const rlp_node of proof) {
        const slicedNode = rlp_node.slice(4).match(/.{1,64}/g).map((x) => "0x" + x)
        console.log({ rlp_node, slicedNode })
        trie_proof.push(slicedNode)
        //trie_proof.push( ethers.decodeRlp(ethers.toBeArray(rlp_node)))
    }

    return trie_proof

}


export function createStoragePositionMapping(key, keyType, mappingPos) {
    const abiCoder = new ethers.AbiCoder()
    const preImage = abiCoder.encode([keyType, "uint256"], [key, mappingPos])
    // console.log({
    //     storageKeyPreImage: preImage,
    //     storageKeyPreImageArr: preImage.slice(2).match(/.{1,64}/g).map((x) => "0x" + x).toString(),
    //     storageKey: ethers.keccak256(preImage)
    // })
    return ethers.keccak256(preImage)
}

export function createStoragePositionMappingPosseidon(key, keyType, mappingPos) {
    const abiCoder = new ethers.AbiCoder()
    //const preImage = abiCoder.encode([keyType, "uint256"],[key, mappingPos])
    const preImage = ethers.zeroPadValue(key, 32) + ethers.zeroPadValue(mappingPos, 32).slice(2)
    const encodedKey = abiCoder.encode([keyType], [key])
    const encodedMappingPos = abiCoder.encode(["uint256"], [mappingPos])
    //console.log({encodedKey,encodedMappingPos, preImage})
    //console.log({preImage})
    return "0x" + poseidon1([preImage]).toString(16)
    //return "0x" + poseidon2([encodedKey, mappingPos]).toString(16)
}

export async function getStorageAt(contractAddress, position, blockNumber, provider) {
    const blockNumberHex = "0x" + blockNumber.toString(16)
    const params = [contractAddress, position, blockNumberHex]
    console.log('eth_getStorageAt', params)
    const storageKey = await provider.send('eth_getStorageAt', params)
    console.log({storageKey})
    return storageKey
}

export async function getProof(contractAddress, storageKey, blockNumber, provider) {
    const blockNumberHex = "0x" + blockNumber.toString(16)

    const params = [contractAddress, [storageKey], blockNumberHex,]
    console.log(`const proof = await provider.send('eth_getProof', ${params})`)
    const proof = await provider.send('eth_getProof', params)
    return proof
}


export async function getCodeHashPosiedon(contract) {

}


export async function getCodeHashKeccak(contract) {

}


async function getMainnetProof() {
    //scroll
    const PROVIDERURL = "https://eth.llamarpc.com"//https://scroll.drpc.org"//"https://scroll-sepolia.drpc.org"
    const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    const blockNumber = await provider.getBlockNumber("latest")

    //weth
    const contractAddress = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    //weth whale
    const lookUpAddress = "0x2fEb1512183545f48f6b9C5b4EbfCaF49CfCa6F3"
    //slot pos for balances of weth contract
    const mappingPosition = "0x03"
    //get possition of mapping value keccak(lookUpAddress, mappingPosition ) 
    const storageKey = createStoragePositionMapping(lookUpAddress, "address", mappingPosition)
    //const storageKey = await getStorageAt(contractAddress, storagePosition, blockNumber, provider)
    //storageKey is just the balance in the mapping?
    const proof = await getProof(contractAddress, storageKey, blockNumber, provider)
    //console.log(proof)
    //console.log({storageKey})
    //console.log({"formattedproof": formatProofNodes(proof.storageProof[0].proof)})

    //await fs.writeFile('./out/mainnetProof.json', JSON.stringify(proof, null, 2));
}

/**
 * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up
 * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
 * hash matches the root of the tree. When processing the proof, the pairs
 * of leafs & pre-images are assumed to be sorted.
 */
function processProof(proof, leaf) {
    let computedHash = leaf;
    for (i = 0; i < proof.length; i++) {
        computedHash = Hashes.commutativeKeccak256(computedHash, proof[i]);
    }
    return computedHash;
}

async function codeHashWifSplit(code, width=3) {
    const poseidonFuncs = [poseidon1,poseidon2,poseidon3,poseidon4,poseidon5,poseidon6,poseidon7,poseidon8,poseidon9,poseidon10,poseidon11,poseidon12,poseidon13,poseidon14,poseidon15,poseidon16]
    const currentPoseidon = poseidonFuncs[width-1]//await buildPoseidon()
    const slicedCode = code.slice(2).match(/.{1,64}/g).reduce((arr,value, i)=>{
        arr[i%width] += ethers.zeroPadValue("0x"+value, 32).slice(2)
        return arr
    },Array(width).fill("0x"))
    
    //make capflag
    const nBytes = code.slice(2).length/2 //nBytes * 2^64
    const capFlag = BigInt(nBytes) * BigInt(2)**BigInt(64)

    //add into arr with 0 bytes 
    const zeroBytes32 = ethers.zeroPadValue(ethers.toBeHex(0), 32)
    const capFlagArr = Array(width).fill(zeroBytes32)
    capFlagArr[0] = ethers.zeroPadValue(ethers.toBeHex(capFlag), 32)

    const codeHashPreImage = capFlagArr.map((x, i)=>x+slicedCode[i].slice(2))
    const splitCodeHash = ethers.toBeHex(currentPoseidon(codeHashPreImage))
    console.log({width,splitCodeHash, codeHashPreImage})//maybe poseidon 18
} 

async function getScollProofMapping() {
    //scroll
    const PROVIDERURL = "https://scroll.drpc.org"//"https://scroll-sepolia.drpc.org"
    const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    const blockNumber =  Number(0x62be1f) //await provider.getBlockNumber("latest")

    //weth
    const contractAddress = "0x5300000000000000000000000000000000000004"
    //weth whale
    const lookUpAddress = "0x4402c128c2337d7a6c4c867be68f7714a4e06429"
    //slot pos for balances of weth contract
    const mappingSlot = "0x00"
    //get possition of mapping value keccak(lookUpAddress, mappingPosition ) 
    const storageKey = createStoragePositionMapping(lookUpAddress, "address", mappingSlot)
    const proof = await getProof(contractAddress, storageKey, blockNumber, provider)
    console.log({proof})
    //cheesy ah test to see if we're in browser
    if(windowIsEmpty === true) {

        await fs.writeFile('./out/scrollProof.json', JSON.stringify(proof, null, 2));
    }
}

export async function getScollProofValue() {
    //scroll
    const PROVIDERURL = "https://scroll.drpc.org"//"https://scroll-sepolia.drpc.org"
    const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    const blockNumber =  Number(0x62be1f) //await provider.getBlockNumber("latest")

    //weth
    const contractAddress = "0x5300000000000000000000000000000000000004"
    //slot pos for balances of weth contract
    const slot = ethers.zeroPadValue("0x03", 32)
    //get possition of mapping value keccak(lookUpAddress, mappingPosition ) 
    //const storageKey = await getStorageAt("0x5300000000000000000000000000000000000004",slot, blockNumber, provider)
    const proof = await getProof(contractAddress, slot, blockNumber, provider)
    console.log({proof})
    //cheesy ah test to see if we're in browser
    if(windowIsEmpty === true) {

        await fs.writeFile('./out/scrollProofValue.json', JSON.stringify(proof, null, 2));
    }

}

function formatHex(bytesLike) {
    if (!bytesLike.toLowerCase().startsWith('0x')) {
        throw new Error(`Not a hex string: ${bytesLike}`)
    }

    bytesLike = String(bytesLike)
    if (
        bytesLike.toLowerCase() === '0' ||
        bytesLike.toLowerCase() === '0x0' ||
        bytesLike.toLowerCase() === '0x00'
    ) {
        // 0 numerical values shall be represented as '0x'
        return '0x'
    } else if (bytesLike.length % 2) {
        // odd
        const evenByteLen = (bytesLike.slice(2).length + 1) / 2
        //zeroPadValue nolonger accepts hex string in v6 but it does return hex string :/
        return ethers.zeroPadValue(ethers.toBeArray(bytesLike), evenByteLen)
    } else {
        return bytesLike
        }
}


export async function getBlockHeaderRlp(blockNumber,provider) {
    // const PROVIDERURL = "https://scroll.drpc.org"//"https://scroll-sepolia.drpc.org"
    // const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    const blockHash = (await provider.getBlock(Number(blockNumber))).hash
    const block = await provider.send('eth_getBlockByHash', [blockHash, false])
    //https://github.com/scroll-tech/go-ethereum/blob/418bc6f728b66ec9eafab3f3b0ceb14078d8a050/core/types/block.go#L69
    const headerData = [
        block.parentHash,       // 32 bytes
        block.sha3Uncles,       // 32 bytes
        block.miner,            // 32 bytes     
        block.stateRoot,        // 32 bytes     
        block.transactionsRoot, // 32 bytes    
        block.receiptsRoot,     // 32 bytes     
        block.logsBloom,        // 256 bytes 
        block.difficulty,       // 32 bytes? = *big.Int   
        block.number,           // 32 bytes? = *big.Int    
        block.gasLimit,         //  8 bytes         
        block.gasUsed,          //  8 bytes   
        block.timestamp,        //  8 bytes                         
        block.extraData,       // 97 bytes? just gues from trying 
        block.mixHash,          // 32 bytes         
        block.nonce,            // 8 bytes   

        // TODO
        // is in testnet not mainnet?
        block.baseFeePerGas,
        // block.withdrawalsRoot,
        // block.blobGasUsed,
        // block.excessBlobGas,
        // block.parentBeaconBlockRoot

    ]
    const formattedHeaderData = headerData.map((bytesLike, i) =>formatHex(bytesLike))
    const rlp = ethers.encodeRlp(formattedHeaderData)
    const offset = 182
    const stateRootFromRlp = "0x"+rlp.slice(2+offset, 2+64+offset)

    // debug
    const isCorrectHash = ethers.keccak256(rlp) === block.hash
    const isCorrectOffset = stateRootFromRlp === block.stateRoot

    console.log("created rlp header: ",{rlp,isCorrectHash, isCorrectOffset, blockHash, blocknum: Number(block.number)})

    return rlp


}
async function main() {

    //await getScollProofMapping()
   //await getScollProofValue()
   //await getBlockHeaderRlp()
}
//await main()