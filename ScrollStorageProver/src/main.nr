use dep::std;
use dep::std::hash::poseidon::bn254::perm;
use dep::std::hash::poseidon;

//used hash_2 from noirs std as example
//https://github.com/noir-lang/noir/blob/8a322998ee60875f7abe4dc222f8fdc20cb0ee0a/noir_stdlib/src/hash/poseidon/bn254.nr#L24
//and from the go-ethereum scroll repo
//https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon.go#L157
pub fn hash_2WithDomain(domain: Field, input: [Field; 2] ) -> Field {
    let mut state = [0; 3];
    state[0] = domain;
    for i in 0..input.len() {
        state[i+1] = input[i];
    }
    perm::x5_3(state)[0]
}

#[test]
fn test_main() {
    let preimage12 = [1,2];
    let hashFixed2 = poseidon::bn254::hash_2(preimage12);
    assert(hashFixed2 == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a); 
    //matches  HashFixed([]*big.Int{1, 2})
    //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L41
    
    //HashFixedWithDomain([]*big.Int{b1, b2}, big.NewInt(256))
    //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L99
    let mut hashFixedDomain = hash_2WithDomain(256, preimage12);
    assert(hashFixedDomain == 0x05390df727dcce2ddb8faa3acb4798ad4e95b74de05e5cc7e40496658913ae85);

    //https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L16
    //first byte specifies node type which is used as the domain
    
    
    //-------------storageKey----------------
    let storageKeyPreImageArr = [0x0000000000000000000000004402c128c2337d7a6c4c867be68f7714a4e06429,0x0000000000000000000000000000000000000000000000000000000000000000];
    let storageKeyPreImageConcat = 0x0000000000000000000000004402c128c2337d7a6c4c867be68f7714a4e064290000000000000000000000000000000000000000000000000000000000000000;

    //ethers.keccak(storageKeyPreImageConcat)
    //identifier of the storage value and contains the key and slot of the mapping 
    let storageKey = 0xdd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff;

    //root of storage proof, used in account proof to walk the merkle path to blockheader
    let storageHash = 0x0d5ae1b455fb8efc1be9a7f90e3b312ecaf3ff46930a6f2e0c3ecfb04cb950cd;

    //--------------valueHash --------------------------------
    //nodeKey := h{256}(storageKey[0:16], storageKey[16:32])
    
    //storageKeySplit padded value
    //leading zeros wont make a difference

    //"0xdd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff".slice(2).match(/.{1,32}/g).map((x) => ethers.zeroPadBytes("0x" + x, 32)).toString()
    let storageKeySplitPadded = [0xdd4d389a3e50efed8ae09dd0fdc3adaf00000000000000000000000000000000,0x1beae58fd2204e19758755085d876cff00000000000000000000000000000000];
    let mut nodeKey = hash_2WithDomain(0x20, storageKeySplitPadded);
    println("storageKeySplitPadded");
    println(nodeKey);

    //no padding
    let storageKeySplit = [0xdd4d389a3e50efed8ae09dd0fdc3adaf,0x1beae58fd2204e19758755085d876cff];
    nodeKey = hash_2WithDomain(0x02, storageKeySplit);
    println("storageKeyPreImageArr");
    println(nodeKey);

    //--------------valueHash --------------------------------
    //valueHash = h{512}(storageValue[0:16], storageValue[16:32])
    
    //ethers.zeroPadBytes("0x05390c89de0c208457",32).slice(2).match(/.{1,32}/g).map((x) => "0x" + x, 32).toString()
    let valueSplitPadded = [0x05390c89de0c20845700000000000000,0x00000000000000000000000000000000];
    println("valueSplitPadded");
    let mut valueHash = hash_2WithDomain(512, valueSplitPadded);
    println(valueHash);


    //ethers.zeroPadBytes("0x05390c89de0c208457",32).slice(2).match(/.{1,32}/g).map((x) => ethers.zeroPadBytes("0x" + x, 32)).toString()
    let valueSplitDoublePadded = [0x05390c89de0c2084570000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000000];
    println("valueSplitDoublePadded");
    let mut valueHash = hash_2WithDomain(512, valueSplitDoublePadded);
    println(valueHash);
    
    //no padding
    let valueSplit = [0x0,0x05390c89de0c208457];
    println("valueSplit");
    valueHash = hash_2WithDomain(0x50, valueSplit);
    println(valueHash);


    //----------leafNodeHash-------------
    //leafNodeHash = h{LeafNodeType}(nodeKey, valueHash)
    let leafNodeType = 0x04;
    let leafNodeHash = hash_2WithDomain(leafNodeType,[nodeKey,valueHash] );
    println("leafNodeHash");
    println(leafNodeHash);
    //leafNodeProofDeconstructed
    // 0x04 
    // 108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a 
    // 01010000 
    // 000000000000000000000000000000000000000000000005390c89de0c208457 
    // 20 
    // dd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff

    //node hash
    //let leafNodeProof = "0x04108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a01010000000000000000000000000000000000000000000000000005390c89de0c20845720dd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff"
    //"0x" + leafNodeProof.slice(4).slice(0,64)
    let leafNodeSibling = 0x108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a;
    let nodeHash = hash_2WithDomain(leafNodeType, [leafNodeSibling, leafNodeHash]);
    println("nodeHash");
    println(nodeHash);
}

