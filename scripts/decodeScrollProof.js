import  {poseidon2}  from "../lib/poseidon-lite-for-scroll/build/index.js"
import {assert, ethers} from "ethers"

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
}

main()