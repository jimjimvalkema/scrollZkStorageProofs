import { ethers } from "ethers";


export function createStoragePositionMapping(key,keyType, mappingPos) {
    const abiCoder = new ethers.AbiCoder()
    const preImage = abiCoder.encode([keyType, "uint256"],[key, mappingPos])
    return ethers.keccak256(preImage)
}

export async function getStorageAt(contractAddress, position, blockNumber, provider) {
    const blockNumberHex = "0x" + blockNumber.toString(16)
    const params = [contractAddress,position,blockNumberHex]
    const storageKey = await provider.send('eth_getStorageAt', params)
    return storageKey

}

export async function getProof(contractAddress, storageKey, blockNumber, provider) {
    const blockNumberHex = "0x" + blockNumber.toString(16)

    const params = [contractAddress,[storageKey],blockNumberHex,]
    console.log(params)

    const proof = await provider.send('eth_getProof', params)
    return proof
}


async function main() {
    const PROVIDERURL = "https://mainnet.infura.io/v3/2LPfLOYBTHSHfLWYSv8xib2Y7OA" //"https://scroll-sepolia.drpc.org"
    const provider = new ethers.JsonRpcProvider(PROVIDERURL)
    const blockNumber = await provider.getBlockNumber("latest")



    const contractAddress = "0x72e4f9F808C49A2a61dE9C5896298920Dc4EEEa9"
    const lookUpAddress = "0xf1B42cc7c1609445620dE4352CD7e58353C3FA74"
    const mappingPosition = "0x1"

    const storagePosition = createStoragePositionMapping(lookUpAddress, "address", mappingPosition)
    const storageKey = await getStorageAt(contractAddress, storagePosition, blockNumber, provider)
    console.log({storageKey, storagePosition})
    const proof = await getProof(contractAddress,storageKey,blockNumber, provider)
    console.log(proof)
    console.log(proof.storageProof[0].proof)
}

await main()