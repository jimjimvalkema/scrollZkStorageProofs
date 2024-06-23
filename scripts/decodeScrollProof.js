import  {poseidon2}  from "../lib/poseidon-lite-for-scroll/build/index.js"
import {N, assert, ethers} from "ethers"
import { ZkTrieNode, NodeTypes } from "./types/ZkTrieNode.js";
import {Zkt} from "./types/Zkt.js"


// https://github.com/scroll-tech/Zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L131  
// NewNodeFromBytes creates a new node by parsing the input []byte.
export function  nodeFromBytes(b) {
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
                throw new Error("ErrNodeBytesBadSize")
                //return nil, ErrNodeBytesBadSize
            }
            //Zkt.HashByteLen = 32
            const childLHash  = b.slice(0,Zkt.HashByteLen)// Zkt.NewHashFromBytes(b.slice(0,Zkt.HashByteLen))
            const childRHash = b.slice(Zkt.HashByteLen, Zkt.HashByteLen*2)// Zkt.NewHashFromBytes(b.slice(Zkt.HashByteLen, Zkt.HashByteLen*2))
            n.childL = new ZkTrieNode({hash:ethers.hexlify(childLHash)})
            n.childR = new ZkTrieNode({hash:ethers.hexlify(childRHash)})

        case NodeTypes.NodeTypeLeaf:
        case NodeTypes.NodeTypeLeaf_New:
            if (b.length < Zkt.HashByteLen+4) {
                throw new Error("ErrNodeBytesBadSize")
                //return nil, ErrNodeBytesBadSize
            }
            n.nodeKey = ethers.hexlify(Zkt.NewHashFromBytes(b.slice(0,Zkt.HashByteLen)));
            const mark = ethers.toNumber(b.slice(Zkt.HashByteLen , Zkt.HashByteLen+4).reverse())
            n.mark = ethers.hexlify(b.slice(Zkt.HashByteLen , Zkt.HashByteLen+4).reverse())
            const preimageLen = mark & 255

            n.compressedFlags = ethers.toBeHex(mark >> 8)
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
        case NodeTypes.NodeTypeEmpty:
        case NodeTypes.NodeTypeEmpty_New:
            break
        default:
            throw new Error("ErrNodeBytesBadSize")
            //return nil, ErrInvalidNodeFound
	}
	return n
}

export function hashNode(node) {
    return poseidon2([node.leftChild, node.righChild], node.type);
}


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

if (!windowIsEmpty) {
    window.hashNode = hashNode;
}

function main() {
    console.log(new ZkTrieNode({type: 4}))
    //HashFixedWithDomain([]*big.Int{b1, b2}, big.NewInt(256))
    //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L99
    const domain = 256
    const preimage = [1,2]
    const hash = ethers.toBeHex(poseidon2(preimage,domain))
    console.log(hash)
    assert(hash === "0x05390df727dcce2ddb8faa3acb4798ad4e95b74de05e5cc7e40496658913ae85")


    // inputs as in proof
    // 0x0611d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040

    // inputs decoded
    // 0x06
    // 11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe
    // 082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040

    const node = new ZkTrieNode({type:0x06})
    node.childL = new ZkTrieNode({hash:"0x11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe"})
    node.childR = new ZkTrieNode({hash:"0x082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040"})

    node.hash = ethers.toBeHex(poseidon2([node.childL.hash, node.childR.hash], node.type))
    console.log(node.hash)
    assert(node.hash === "0x084a2eb35e4cfd22b840cebde52db3567f0d46b99f69378a6d36361f367153ca")

    const nodeBytes = ethers.toBeArray("0x0420e9fb498ff9c35246d527da24aa1710d2cc9b055ecf9a95a8a2a11d3d836cdf050800000000000000000000000000000000000000000000000016ef00000000000000000000000000000000000000000000000000000000000001395d857ace5efb1c6e098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51e8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be205300000000000000000000000000000000000004000000000000000000000000")
    console.log(nodeFromBytes(nodeBytes))
}

main()