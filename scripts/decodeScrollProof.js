import  {poseidon2}  from "../lib/poseidon-lite-for-scroll/build/index.js"
import {N, assert, ethers} from "ethers"
import { MptNode } from "./types/MptNode.js";


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
    //HashFixedWithDomain([]*big.Int{b1, b2}, big.NewInt(256))
    //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L99
    const domain = 256n
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

    const node = new MptNode()
    node.childL = "0x11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe"
    node.childR = "0x082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040"
    node.setType(0x06)

    node.hash = ethers.toBeHex(poseidon2([node.childL, node.childR], BigInt(node.type)))
    console.log(node.hash)
    assert(node.hash === "0x084a2eb35e4cfd22b840cebde52db3567f0d46b99f69378a6d36361f367153ca")
}

main()