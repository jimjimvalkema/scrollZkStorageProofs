import  {poseidon2}  from "../lib/poseidon-lite-for-scroll/build/index.js"
import {N, assert, ethers} from "ethers"
import { ZkTrieNode, NodeTypes, leafTypes } from "./types/ZkTrieNode.js";
import {Zkt} from "./types/Zkt.js"
import * as fs from 'node:fs/promises';

import storageProofMapping from './out/scrollProofMapping.json' assert {type: 'json'}

//----some stuff so i can test things in the browser console (i prefer it)
let windowIsEmpty = true
// Check if the environment is Node.js
if (typeof process === "object" &&
    typeof require === "function") {
    windowIsEmpty = true;
} else {
    if (typeof window === "object") {
        windowIsEmpty = false;
    }
}

// decoding--------------

// https://github.com/scroll-tech/Zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L131  
// NewNodeFromBytes creates a new node by parsing the input []byte.
export function  nodeFromBytes(b) {
    if (typeof(b) === "string") {
        b = ethers.toBeArray(b)
    }
	if (b.length < 1) {
        throw new Error('ErrNodeBytesBadSize');
	}
	const n = new ZkTrieNode({type: b[0]});
	b = b.slice(1);
	switch (n.type) {
        case NodeTypes.NodeTypeParent:
        case NodeTypes.NodeTypeBranch_0:
        case NodeTypes.NodeTypeBranch_1: 
        case NodeTypes.NodeTypeBranch_2: 
        case NodeTypes.NodeTypeBranch_3:
            if (b.length != 2*Zkt.HashByteLen) {
                throw new Error(`ErrNodeBytesBadSize (b.length < ${2*Zkt.HashByteLen}, b.length=${b.length})`)
                //return nil, ErrNodeBytesBadSize
            }
            //Zkt.HashByteLen = 32
            const childLHash  = b.slice(0,Zkt.HashByteLen)// Zkt.NewHashFromBytes(b.slice(0,Zkt.HashByteLen))
            const childRHash = b.slice(Zkt.HashByteLen, Zkt.HashByteLen*2)// Zkt.NewHashFromBytes(b.slice(Zkt.HashByteLen, Zkt.HashByteLen*2))
            n.childL = new ZkTrieNode({hash:ethers.hexlify(childLHash)})
            n.childR = new ZkTrieNode({hash:ethers.hexlify(childRHash)})
            break

        case NodeTypes.NodeTypeLeaf:
        case NodeTypes.NodeTypeLeaf_New:
            if (b.length < Zkt.HashByteLen+4) {
                throw new Error("ErrNodeBytesBadSize")
                //return nil, ErrNodeBytesBadSize
            }
            n.nodeKey = ethers.hexlify(Zkt.NewHashFromBytes(b.slice(0,Zkt.HashByteLen)));
            n.hashPathBools =  BigInt(n.nodeKey).toString(2).split('').map(x => x === '1').reverse()
            const mark = ethers.toNumber(b.slice(Zkt.HashByteLen , Zkt.HashByteLen+4).reverse())
            n.mark = ethers.hexlify(b.slice(Zkt.HashByteLen , Zkt.HashByteLen+4).reverse())
            const preimageLen = mark & 255
            const compressedFlagsUnpadded = (mark >> 8).toString(2).split('').map(x => x === '1').reverse()

            // TODO not sure if they need to be padded since it doesnt happen in go. 
            // but it might have something todo with js numbers beind different?
            // or simply because they are compressed so the zeros at the end are stripped.
            n.compressedFlags = [...compressedFlagsUnpadded, ...Array(preimageLen-compressedFlagsUnpadded.length).fill(false)]
            let _valuePreimage = Array(preimageLen).fill(new Uint8Array(Array(32).fill(0)))//make([]Zkt.Byte32, preimageLen)
            let curPos = Zkt.HashByteLen + 4
            if (b.length < curPos+preimageLen*32+1) {
                throw new Error("ErrNodeBytesBadSize")
                //return nil, ErrNodeBytesBadSize
            }
            for (let i = 0; i < preimageLen; i++) {
                //copy(n.ValuePreimage[i][:], b[i*32+curPos:(i+1)*32+curPos])
                _valuePreimage[i] =  b.slice(Number(i*32+curPos), Number((i+1)*32+curPos))
                
            }
            n.valuePreimage = _valuePreimage.map((value)=>ethers.hexlify(value))
            curPos += preimageLen * 32
            const preImageSize = b[curPos]
            curPos += 1
            if (preImageSize !== 0) {
                if (b.length < curPos+preImageSize) {
                    throw new Error("ErrNodeBytesBadSize")
                    //return nil, ErrNodeBytesBadSize
                }
                //Zkt.Byte32 = uint8 with 32 zeros
                //_keyPreimage = structuredClone(Zkt.Byte32)
                //copy(n.KeyPreimage[:], b[curPos:curPos+preImageSize])
                n.keyPreimage =  ethers.hexlify(b.slice(Number(curPos),Number(curPos+preImageSize)))
            }
            break
        case NodeTypes.NodeTypeEmpty:
        case NodeTypes.NodeTypeEmpty_New:
            break
        default:
            throw new Error("ErrNodeBytesBadSize")
            //return nil, ErrInvalidNodeFound
	}
	return n
}


// hashing--------------------
function splitArr(_arr,groupSize) {
    // prevent bugs if we dont modify existing arr
    const arr = structuredClone(_arr)
    const newArrLen =  Math.ceil(arr.length/groupSize)
    const newArr = []
    for (let index = 0; index < newArrLen; index++) {
        newArr.push(arr.splice(0,2))
    }
    return newArr
}


export function hashSplitVal(val) {
    const domain = 512
    const first16bytes = val.slice(0,32+2)
    const last16bytes = "0x"+val.slice(32+2,64+2)
    return ethers.toBeHex(poseidon2([first16bytes, last16bytes],domain))
}


export function hashElems(domain,elems) {
    const groupedArr = splitArr(elems,2)
    const hashedElems = groupedArr.map((preImage)=>{
        if(preImage.length === 2) {
            return ethers.toBeHex(poseidon2(preImage, domain))
        } else {
            return preImage[0]
        }
    })
    if (hashedElems.length === 2) {
        hashedElems.reverse()
    }

    let resHash
    if (hashedElems.length === 1 ) {
        resHash = hashedElems[0]
    } else if (hashedElems.length === 2) {
        // TODO hashedElems.reverse() might break things when elems.length > 4 and a even lenght.
        // it asumes that when hashedElems === 2 the last item is a left over.
        // maybe track left overs? idk how to deal with left uneven left overs.
        // maybe its normal? maybe its just results in a unbalanced tree part being on the left?
        // shouldn't be a issue with storage proof though since their value preImages,
        // are either lenght 1 (storage leaf) or 5 (account leaf)
        resHash = ethers.toBeHex(poseidon2(hashedElems.reverse(), domain))
    } else {
        resHash = hashElems(domain, hashedElems)
    }
    return resHash
}

export function getCompressedPreimage(node) {
    const valuesWithCompressed = node.valuePreimage.map((preImage, index)=>{
        if (node.compressedFlags[index]) {
            return hashSplitVal(preImage)
        } else {
            return preImage
        }
    })
    return valuesWithCompressed
}

export function getValueHash(node) {
    const valuesWithCompressed = getCompressedPreimage(node)
    const domain = 256*node.valuePreimage.length
    const valueHash =  hashElems(domain, valuesWithCompressed)
    return valueHash
}

/**
 * 
 * @param {ZkTrieNode} node 
 * @returns 
 */
export function hashNode(node) {
    if (leafTypes.includes(node.type)) {
        const valueHash = getValueHash(node)
        node.hash = ethers.toBeHex(poseidon2([node.nodeKey, valueHash], node.type))

    } else {
        node.hash = ethers.toBeHex(poseidon2([node.childL.hash, node.childR.hash], node.type));
    }
    
    return node.hash
}

//proofing --------------------
export const magicSMTBytes = new TextEncoder().encode("THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI")//[]byte("THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI")
export function isMagicBytes(nodeBytes) {
    return nodeBytes === ethers.hexlify(magicSMTBytes)
}

export function getHashPathFromProof(_proof) {
    //pre process proof
    const proof = _proof.slice().reverse()
    if (isMagicBytes(proof[0])) {proof.shift()}

    //get hasPathBools from leaf
    const leafNode = nodeFromBytes(proof.shift())
    const hashPathBools = leafNode.hashPathBools.slice(0, proof.length).reverse()

    //init
    const hashPath = []
    const nodeTypes = []
    
    for (const [index,nodeBytes] of proof.entries()) {
        const node = nodeFromBytes(nodeBytes)
        nodeTypes.push(node.type)

        const hashRight = hashPathBools[index]
        if (hashRight) {
            hashPath.push(node.childL.hash)
        } else {
            hashPath.push(node.childR.hash)
        }
    }

    return {hashPath, nodeTypes, leafNode}
}

/**
 * 
 * @param {ethers.BytesLike[]} hashPath 
 * @param {number[]} nodeTypes 
 * @param {ZkTrieNode} leafNode 
 * @returns {ethers.BytesLike} 
 */
export function verifyHashPath(hashPath, nodeTypes, leafNode ) {
    let currentHash = hashNode(leafNode)
    const hashPathBools = leafNode.hashPathBools.slice(0,hashPath.length).reverse()

    for (const [index, hash] of hashPath.entries()) {
        const hashRight = hashPathBools[index] 
        if (hashRight === undefined){throw new Error("undefined :(")}
        if (hashRight) {
            //console.log(`left: ${hash}, right: ${currentHash},\nnodeType: ${nodeTypes[index]}\n`)
            currentHash = ethers.toBeHex(poseidon2([hash ,currentHash], nodeTypes[index]))
        } else {
            //console.log(`left: ${currentHash}, right: ${hash},\nnodeType: ${nodeTypes[index]}\n`)
            currentHash = ethers.toBeHex(poseidon2([currentHash ,hash], nodeTypes[index]))
        }        
    }
    return currentHash
}


if (!windowIsEmpty) {
    window.hashNode = hashNode;
    window.verifyProof = verifyProof;
}

async function main() {
    //HashFixedWithDomain([]*big.Int{b1, b2}, big.NewInt(256))
    //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L99
    const domain = 256
    const preimage = [1,2]
    const hash = ethers.toBeHex(poseidon2(preimage,domain))
    assert(hash === "0x05390df727dcce2ddb8faa3acb4798ad4e95b74de05e5cc7e40496658913ae85")

    const node = new ZkTrieNode({type:0x06})
    node.childL = new ZkTrieNode({hash:"0x11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe"})
    node.childR = new ZkTrieNode({hash:"0x082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040"})

    node.hash = ethers.toBeHex(poseidon2([node.childL.hash, node.childR.hash], node.type))
    assert(node.hash === "0x084a2eb35e4cfd22b840cebde52db3567f0d46b99f69378a6d36361f367153ca", 
        "Node hash doesnt match"
    )

    const nodeBytesStorageLeaf = ethers.toBeArray("0x04108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a0101000000000000000000000000000000000000000000000000000000900661d8af4c8620dd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff")
    const storageLeaf = nodeFromBytes(nodeBytesStorageLeaf)
    hashNode(storageLeaf);
    assert(storageLeaf.hash === "0x11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe",
        "storageLeafHash doesnt match"
    )

    const nodeBytesAccountLeaf = ethers.toBeArray("0x0420e9fb498ff9c35246d527da24aa1710d2cc9b055ecf9a95a8a2a11d3d836cdf050800000000000000000000000000000000000000000000000016ef00000000000000000000000000000000000000000000000000000000000001395d857ace5efb1c6e098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51e8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be205300000000000000000000000000000000000004000000000000000000000000")
    const accountLeaf = nodeFromBytes(nodeBytesAccountLeaf)
    hashNode(accountLeaf);
    assert(accountLeaf.hash === "0x1773e4a9875437b5692acfc4caf46b4db0666b1d98af4dd58fe2d03b6e20f4bb",
        "accountLeafHash doesnt match"
    )

    const nodeBytesBranch = ethers.toBeArray("0x090cc290e414db319dd2e2e8d43c0058c425b26221b32cc36d1d3941b34d396e941590f4aaba59ff46a09d7a6a152cbf27280c2fbaa4bb94aa3eefab3bbd7d6e19")
    const branch = nodeFromBytes(nodeBytesBranch)
    hashNode(branch);
    assert(branch.hash === "0x098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51",
        "branchNodeHash doesnt match"
    )


    //extract hashpath and verify
    const {hashPath, nodeTypes, leafNode} = getHashPathFromProof(storageProofMapping.storageProof[0].proof)
    const rootHash = verifyHashPath(hashPath, nodeTypes, leafNode)
    assert(rootHash === storageProofMapping.storageHash, 
        "failed to verify hashPath"
    )
}

await main()

