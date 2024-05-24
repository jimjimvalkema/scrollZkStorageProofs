import { ethers } from "ethers";
// import { buildPoseidon, buildPoseidonWasm, buildPoseidonOpt } from "circomlibjs";
import {poseidon1, poseidon2} from "poseidon-lite";
import * as fs from 'node:fs/promises';


export function createStoragePositionMapping(key,keyType, mappingPos) {
    const abiCoder = new ethers.AbiCoder()
    const preImage = abiCoder.encode([keyType, "uint256"],[key, mappingPos])
    return ethers.keccak256(preImage)
}

export function createStoragePositionMappingPosseidon(key,keyType, mappingPos) {
    const abiCoder = new ethers.AbiCoder()
    //const preImage = abiCoder.encode([keyType, "uint256"],[key, mappingPos])
    const preImage = ethers.zeroPadValue(key, 32) + ethers.zeroPadValue(mappingPos, 32).slice(2)
    const encodedKey = abiCoder.encode([keyType],[key])
    const encodedMappingPos = abiCoder.encode(["uint256"],[mappingPos])
    //console.log({encodedKey,encodedMappingPos, preImage})
    console.log({preImage})
    return "0x" + poseidon1([preImage]).toString(16)
    //return "0x" + poseidon2([encodedKey, mappingPos]).toString(16)
}

export async function getStorageAt(contractAddress, position, blockNumber, provider) {
    const blockNumberHex = "0x" + blockNumber.toString(16)
    const params = [contractAddress,position,blockNumberHex]
    //console.log({contractAddress,position,blockNumberHex})
    const storageKey = await provider.send('eth_getStorageAt', params)
    return storageKey
}

export async function getProof(contractAddress, storageKey, blockNumber, provider) {
    const blockNumberHex = "0x" + blockNumber.toString(16)

    const params = [contractAddress,[storageKey],blockNumberHex,]

    const proof = await provider.send('eth_getProof', params)
    return proof
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
        const storageKey =  createStoragePositionMapping(lookUpAddress, "address", mappingSlot)
        //const storageKey = await getStorageAt(contractAddress, storagePosition, blockNumber, provider)
        //storageKey is just the balance in the mapping?
        const proof = await getProof(contractAddress,storageKey,blockNumber, provider)
        console.log(proof)
        const storageSlotPreimage = ethers.zeroPadValue(lookUpAddress, 32) + ethers.zeroPadValue(mappingSlot, 32).slice(2)
        console.log(
            {storageValue: proof.storageProof[0].value},//, expectedValue: }
            {storageKey: proof.storageProof[0].key, expectedKey: ethers.keccak256(storageSlotPreimage)})
    
        await fs.writeFile('./out/scrollProof.json', JSON.stringify(proof, null, 2));
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
    const proof = await getProof(contractAddress,storageKey,blockNumber, provider)
    console.log(proof)
    console.log({storageKey})

    await fs.writeFile('./out/mainnetProof.json', JSON.stringify(proof, null, 2));
}

async function main() {
    getScollProof()
    getMainnetProof()
}

await main()