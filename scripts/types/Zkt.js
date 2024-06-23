// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L10
// just a stripped down version for now
export class Zkt {
    constructor() {
        Object.freeze(Zkt)
    }

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