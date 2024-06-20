import { encryptKeystoreJson, ethers } from "ethers";
import { buildPoseidon, buildPoseidonWasm, buildPoseidonOpt } from "circomlibjs";
import { 
    poseidon1,poseidon2,poseidon3,poseidon4,poseidon5,poseidon6,poseidon7,poseidon8,poseidon9,poseidon10,poseidon11,poseidon12,poseidon13,poseidon14,poseidon15,poseidon16 
} from "poseidon-lite";

import * as fs from 'node:fs/promises';
import * as snarkjs from "snarkjs"


//----some stuff so i can test things in the browser console (i prefer it)
let windowIsEmpty = true
// Check if the environment is Node.js
if (typeof process === "object" &&
    typeof require === "function") {
    windowIsEmpty = true;
} else {
    console.log("scdsda")
    if (typeof window === "object") {
        // Check if the environment is a Browser
        console.log(window)
        windowIsEmpty = false;
        window.ethers = ethers
        window.poseidon1 = poseidon1
        window.poseidon2 = poseidon2
        window.getProof = getProof
        window.NewNodeFromBytes = NewNodeFromBytes
        window.DecodeSMTProof = DecodeSMTProof
    }

}

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L10
// just a stripped down version for now
class zkt {
    // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/hash.go#L48
    // HashByteLen is the length of the Hash byte array
    static HashByteLen= 32 
    
    //type Byte32 [32]byte
    static Byte32 = new Uint8Array(Array(32).fill(0))

    // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/hash.go#L119
    // NewHashFromBytes returns a *Hash from a byte array considered to be
    // a represent of big-endian integer, it swapping the endianness
    // in the process.

    //mostly for type conversion in go impl but here it just reverses bytes
    static NewHashFromBytes(byte) {
        return byte //.reverse()
    }

}
Object.freeze(zkt)

// NodeType defines the type of node in the MT.
// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L16
const NodeType = {
	// NodeTypeParent indicates the type of parent Node that has children.
	NodeTypeParent: 0,
	// NodeTypeLeaf indicates the type of a leaf Node that contains a key &
	// value.
	NodeTypeLeaf: 1,
	// NodeTypeEmpty indicates the type of an empty Node.
	NodeTypeEmpty: 2,

	// DBEntryTypeRoot indicates the type of a DB entry that indicates the
	// current Root of a MerkleTree
	DBEntryTypeRoot: 3,

	NodeTypeLeaf_New : 4,
	NodeTypeEmpty_New: 5,
	// branch node for both child are terminal nodes
	NodeTypeBranch_0: 6,
	// branch node for left child is terminal node and right child is branch
	NodeTypeBranch_1: 7,
	// branch node for left child is branch node and right child is terminal
	NodeTypeBranch_2: 8,
	// branch node for both child are branch nodes
	NodeTypeBranch_3: 9.
}
Object.freeze(NodeType)

// Node is the struct that represents a node in the MT. The node should not be
// modified after creation because the cached key won't be updated.
class Node {
    // Type is the type of node in the tree.
	Type //NodeType
	// ChildL is the node hash of the left child of a parent node.
	ChildL //*zkt.Hash
	// ChildR is the node hash of the right child of a parent node.
	ChildR //*zkt.Hash
	// NodeKey is the node's key stored in a leaf node.
	NodeKey //*zkt.Hash
	// ValuePreimage can store at most 256 byte32 as fields (represnted by BIG-ENDIAN integer)
	// and the first 24 can be compressed (each bytes32 consider as 2 fields), in hashing the compressed
	// elemments would be calculated first
	ValuePreimage //[]zkt.Byte32
	// CompressedFlags use each bit for indicating the compressed flag for the first 24 fields
	CompressedFlags //uint32
	// nodeHash is the cache of the hash of the node to avoid recalculating
	nodeHash //*zkt.Hash
	// valueHash is the cache of the hash of valuePreimage to avoid recalculating, only valid for leaf node
	valueHash //*zkt.Hash
	// KeyPreimage is the original key value that derives the NodeKey, kept here only for proof
	KeyPreimage //*zkt.Byte32
    constructor ({Type}={}) {
        this.Type = Type
    }

}

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L131  
// NewNodeFromBytes creates a new node by parsing the input []byte.
export function  NewNodeFromBytes(b) {
	if (b.length < 1) {
        throw new Error('ErrNodeBytesBadSize');
	}
	const n = new Node({Type: b[0]});
    console.log(b[0])
	b = b.slice(1);
	switch (n.Type) {
        case NodeType.NodeTypeParent:
        case NodeType.NodeTypeBranch_0:
        case NodeType.NodeTypeBranch_1: 
        case NodeType.NodeTypeBranch_2: 
        case NodeType.NodeTypeBranch_3:
            if (b.length != 2*zkt.HashByteLen) {
                throw new Error("ErrNodeBytesBadSize")
                //return nil, ErrNodeBytesBadSize
            }
            n.ChildL = zkt.NewHashFromBytes(b.slice(0,zkt.HashByteLen))
            n.ChildR = zkt.NewHashFromBytes(b.slice(zkt.HashByteLen, zkt.HashByteLen*2))

        case NodeType.NodeTypeLeaf:
        case NodeType.NodeTypeLeaf_New:
            if (b.length < zkt.HashByteLen+4) {
                throw new Error("ErrNodeBytesBadSize")
                //return nil, ErrNodeBytesBadSize
            }
            n.NodeKey = zkt.NewHashFromBytes(b.slice(0,zkt.HashByteLen));
            const mark = ethers.toBigInt(b.slice(zkt.HashByteLen , zkt.HashByteLen+4).reverse())
            console.log(ethers.hexlify(b.slice(zkt.HashByteLen , zkt.HashByteLen+4)))
            const preimageLen = mark & 255n
            console.log({preimageLen, mark})
            n.CompressedFlags = mark >> 8n
            n.ValuePreimage = Array(preimageLen).fill(new Uint8Array(Array(32).fill(0)))//make([]zkt.Byte32, preimageLen)
            let curPos = BigInt(zkt.HashByteLen) + 4n
            if (b.length < curPos+preimageLen*32n+1n) {
                throw new Error("ErrNodeBytesBadSize")
                //return nil, ErrNodeBytesBadSize
            }
            for (let i = 0n; i < preimageLen; i++) {
                //copy(n.ValuePreimage[i][:], b[i*32+curPos:(i+1)*32+curPos])
                console.log(i*32n+curPos, (i+1n)*32n+curPos)
                n.ValuePreimage[i] =  b.slice(Number(i*32n+curPos), Number((i+1n)*32n+curPos))
                
            }
            curPos += preimageLen * 32n
            const preImageSize = BigInt(b[curPos])
            curPos += 1n
            //TODO see if we realy need bigint
            if (preImageSize != 0) {
                if (b.length < curPos+preImageSize) {
                    throw new Error("ErrNodeBytesBadSize")
                    //return nil, ErrNodeBytesBadSize
                }
                n.KeyPreimage = structuredClone(zkt.Byte32)
                console.log(ethers.hexlify(n.KeyPreimage))
                //copy(n.KeyPreimage[:], b[curPos:curPos+preImageSize])
                n.KeyPreimage =  b.slice(Number(curPos),Number(curPos+preImageSize))
                console.log(ethers.hexlify(n.KeyPreimage))
            }
        case NodeType.NodeTypeEmpty, NodeType.NodeTypeEmpty_New:
            break
        default:
            console.log(n)
            throw new Error("ErrNodeBytesBadSize")
            //return nil, ErrInvalidNodeFound
	}
	return n
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
    console.log({
        storageKeyPreImage: preImage,
        storageKeyPreImageArr: preImage.slice(2).match(/.{1,64}/g).map((x) => "0x" + x).toString(),
        storageKey: ethers.keccak256(preImage)
    })
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
    //console.log({contractAddress,position,blockNumberHex})
    const storageKey = await provider.send('eth_getStorageAt', params)
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



async function getScollProof() {
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
   
    // const storageValue = ethers.zeroPadValue(ethers.toBeArray("0x1ac50393b5e904485"), 32)
    // const valueHash = poseidon2(["0x0" + storageValue.slice(2, 34), "0x0" + storageValue.slice(34, 66)])
    // const keyValuePadded = ethers.zeroPadBytes(lookUpAddress, 32).slice(2)
    // const keyHash = ethers.toBeHex(poseidon2(["0x0" + keyValuePadded.slice(0, 16), "0x0" + keyValuePadded.slice(16, 32)]))
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

async function main() {

    await getScollProof()
}

await main()