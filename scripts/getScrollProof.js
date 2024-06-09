import { encryptKeystoreJson, ethers } from "ethers";
window.ethers = ethers
import { buildPoseidon, buildPoseidonWasm, buildPoseidonOpt } from "circomlibjs";
import { 
    poseidon1,poseidon2,poseidon3,poseidon4,poseidon5,poseidon6,poseidon7,poseidon8,poseidon9,poseidon10,poseidon11,poseidon12,poseidon13,poseidon14,poseidon15,poseidon16 
} from "poseidon-lite";
window.poseidon1 = poseidon1
window.poseidon2 = poseidon2
window.poseidon3 = poseidon3
window.poseidon16 = poseidon16
import * as fs from 'node:fs/promises';
import * as snarkjs from "snarkjs"

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
    const blockNumber = await provider.getBlockNumber("latest")

    //weth
    const contractAddress = "0x5300000000000000000000000000000000000004"
    //weth whale
    const lookUpAddress = "0x4402c128c2337d7a6c4c867be68f7714a4e06429"
    //slot pos for balances of weth contract
    const mappingSlot = "0x00"
    //get possition of mapping value keccak(lookUpAddress, mappingPosition ) 
    const storageKey = createStoragePositionMapping(lookUpAddress, "address", mappingSlot)
    //const storageKey = await getStorageAt(contractAddress, storagePosition, blockNumber, provider)
    //storageKey is just the balance in the mapping?
    const proof = await getProof(contractAddress, storageKey, blockNumber, provider)
    //console.log(proof)
    const storageSlotPreimage = ethers.zeroPadValue(lookUpAddress, 32) + ethers.zeroPadValue(mappingSlot, 32).slice(2)
    //console.log(
    // {storageValue: proof.storageProof[0].value},//, expectedValue: }
    // {storageKey: proof.storageProof[0].key, expectedKey: ethers.keccak256(storageSlotPreimage)})

    //await fs.writeFile('./out/scrollProof.json', JSON.stringify(proof, null, 2));

    // const valHi = storageKey.slice(0,16)
    // const valLo = storageKey.slice(16,32)
    // const nodeKey = h(valHi, valLo)

    //const valueHash = poseidon1(storageValue.slice(0,16), storageValue.slice(16,32))


    // const keccakCodeHash = "0xe8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14";
    // const poseidonCodeHash = "0x136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be"
    const storageValue = ethers.zeroPadValue(ethers.toBeArray("0x1ac50393b5e904485"), 32)
    //console.log(["0x0"+storageValue.slice(2,34), "0x0"+storageValue.slice(34,66)], storageValue)
    const valueHash = poseidon2(["0x0" + storageValue.slice(2, 34), "0x0" + storageValue.slice(34, 66)])
    //console.log({valueHash:ethers.toBeHex(valueHash)})
    const keyValuePadded = ethers.zeroPadBytes(lookUpAddress, 32).slice(2)
    const keyHash = ethers.toBeHex(poseidon2(["0x0" + keyValuePadded.slice(0, 16), "0x0" + keyValuePadded.slice(16, 32)]))
    //console.log("should  be same bro :", keyHash, proof.storageProof[0].key, ethers.keccak256(storageSlotPreimage))
    //console.log(valueHash)
    //console.log({ "formattedproof": formatProofNodes(proof.storageProof[0].proof) })
    //const leafNodeHash = h(h(1, nodeKey), valueHash)



    // const valueHash =
    //             h(
    //                 h(
    //                     h(nonce||codesize||0, balance),
    //                     h(
    //                         storageRoot,
    //                         h(keccakCodeHash.slice(0,16), keccakCodeHash.slice(16,32)), // convert Keccak codehash to a field element
    //                     ),
    //                 ),
    //                 poseidonCodeHash,)


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

    //await getScollProof()
    const PROVIDERURL = "https://scroll.drpc.org"//"https://scroll-sepolia.drpc.org"
    const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    let code = "0x"+ (await provider.getCode("0x5300000000000000000000000000000000000004")).slice(2)
    const nBytes = code.slice(2).length/2 //nBytes * 2^64
    const capFlag = BigInt(nBytes) * BigInt(2)**BigInt(64)
    //code = ethers.zeroPadValue(ethers.toBeHex(capFlag),32)+code.slice(2)
    for (let index = 1; index < 17; index++) {
        await codeHashWifSplit(code, index)
    }
    window.code = code
    

    console.log({code})
    //console.log(`[${((""+code.slice(2)).match(/.{1,64}/g).map((x) => "\"0x" + x+"\""))}]`)
    const codeKeccakEthers = ethers.keccak256(ethers.toBeArray(code))
    const codeNoPrefix = code.slice(2)

    const poseidonCircom = await buildPoseidon()
    window.poseidonCircom = poseidonCircom
    const codePoseidonCircom = ethers.hexlify(poseidonCircom([code]))
    const codePoseidonLite = ethers.toBeHex(poseidon1([code]))
    const codePoseidon2Lite = ethers.toBeHex(poseidon2(["0x"+codeNoPrefix.slice(0,codeNoPrefix.length/2), "0x"+codeNoPrefix.slice(codeNoPrefix.length/2,codeNoPrefix.length)]))
    const codePoseidon2LiteWif254 = ethers.toBeHex(poseidon2(["0x"+BigInt(254).toString(16), code]))
    const codePoseidonLiteRevBytes = ethers.hexlify(ethers.toBeArray(codePoseidonLite).reverse())
    const codePoseidonCircomRevBytes = ethers.hexlify(ethers.toBeArray(codePoseidonCircom).reverse())
    const circomPoseidonWif254 = ethers.hexlify(poseidonCircom([code],ethers.zeroPadBytes("0x"+BigInt(254).toString(16), 32)))

    const codeRevBytes = ethers.hexlify(ethers.toBeArray(code).reverse())
    console.log(codeRevBytes)
    console.log(`[${((""+codeRevBytes.slice(2)).match(/.{1,64}/g).map((x) => "0x" + x)).toString()}]`)
    const codePoseidonCircomRevBytesIn = ethers.hexlify(poseidonCircom([codeRevBytes]))
    const codePoseidonLiteRevBytesIn = ethers.toBeHex(poseidon1([codeRevBytes]))

    const codePoseidonExpected = "0x136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be"
    const codeKeccakExpected = "0xe8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14"
    console.log({codePoseidonExpected, 
        codePoseidonCircom,circomPoseidonWif254,codePoseidonLite, 
        codePoseidonLiteRevBytesIn, codePoseidonCircomRevBytesIn,
        codePoseidonLiteRevBytes, codePoseidonCircomRevBytes,
        codePoseidon2Lite,codePoseidon2LiteWif254
    })

    const poseidon2Wif0 =  ethers.toBeHex(poseidon2(["0x"+codeNoPrefix.slice(0,codeNoPrefix.length/2), "0x"+codeNoPrefix.slice(codeNoPrefix.length/2, codeNoPrefix.length)]))
    const poseidon2Wif01st = ethers.toBeHex(poseidon2([512, code]))
    console.log({codePoseidonExpected, poseidon2Wif0, poseidon2Wif01st})
    console.log({codeKeccakExpected, codeKeccakEthers})
    console.log(ethers.toBeHex(poseidon1([ethers.zeroPadBytes(ethers.toBeArray("0xc0fee"), 32)])), ethers.hexlify(poseidonCircom([ethers.zeroPadBytes(ethers.toBeArray("0xc0fee"), 32)])))
    
    //h{512}(keccakCodeHash[0:16], keccakCodeHash[16:32])
    const codeKeccakSplit = ["0x"+codeKeccakEthers.slice(2).slice(0,16), "0x"+codeKeccakEthers.slice(2).slice(16,32)]
    const hashedKeccakCircomSplit =  ethers.hexlify(poseidonCircom(codeKeccakSplit))
    const hashKeccakPliteSplit = ethers.toBeHex(poseidon2(codeKeccakSplit))
    const hashedKeccakCircom =  ethers.hexlify(poseidonCircom([codeKeccakEthers]))
    const hashKeccakPlite = ethers.toBeHex(poseidon1([codeKeccakEthers]))
    console.log({
        hashedKeccakCircomSplit,
        hashKeccakPliteSplit,
        hashedKeccakCircom,
        hashKeccakPlite
    })
    

    const circomWifPadding = ethers.hexlify(poseidonCircom(["0x0"+code.slice(2)]))
    const poseidonLiteWifPadding =  ethers.toBeHex(poseidon1(["0x0"+code.slice(2)]))
    console.log({
        circomWifPadding,
        poseidonLiteWifPadding,
        codePoseidonExpected


        
    })
    //await fs.writeFile('./out/scrollCode.json', JSON.stringify(code, null, 2));

    //getMainnetProof()
}

await main()