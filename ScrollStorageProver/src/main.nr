use dep::std;
use dep::std::hash::poseidon;
use dep::std::hash::poseidon::bn254::perm;

global HASH_DOMAIN_ELEMS_BASE:Field = 256; // TODO maybe change to u8 ??
global HASH_DOMAIN_BYTE32:Field     = 2 * HASH_DOMAIN_ELEMS_BASE;

//used hash_2 from noirs std as example
//https://github.com/noir-lang/noir/blob/8a322998ee60875f7abe4dc222f8fdc20cb0ee0a/noir_stdlib/src/hash/poseidon/bn254.nr#L24
//and from the go-ethereum scroll repo
//https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon.go#L157
pub fn hash_2_with_domain(domain: Field, input: [Field; 2]) -> Field {
    let mut state = [0; 3];
    state[0] = domain;
    for i in 0..input.len() {
        state[i+1] = input[i];
    }
    perm::x5_3(state)[0]
}

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L92
// Node is the struct that represents a node in the MT. The node should not be
// modified after creation because the cached key won't be updated.
struct Node {
    // Type is the type of node in the tree.
    Type: Field,                // NodeType u8 //type NodeType byte

    // ChildL is the node hash of the left child of a parent node.
    ChildL: Field,              // *zkt.Hash
    // NodeKey is the node's key stored in a leaf node.
    ChildR: Field,              // *zkt.Hash

    // NodeKey is the node's key stored in a leaf node.
    NodeKey: Field,             // *zkt.Hash

    // ValuePreimage can store at most 256 byte32 as fields (represnted by BIG-ENDIAN integer)
	// and the first 24 can be compressed (each bytes32 consider as 2 fields), in hashing the compressed
	// elemments would be calculated first
    ValuePreimage: [[u8;32]],  // []zkt.Byte32 

    // CompressedFlags use each bit for indicating the compressed flag for the first 24 fields
    CompressedFlags: u32,       // uint32
    // nodeHash is the cache of the hash of the node to avoid recalculating
    nodeHash: Field,            // *zkt.Hash
    // value_hash is the cache of the hash of valuePreimage to avoid recalculating, only valid for leaf node
    value_hash: Field,           // *zkt.Hash
    // KeyPreimage is the original key value that derives the NodeKey, kept here only for proof
    KeyPreimage: [u8;32]          // *zkt.Byte32
}

pub fn split_byte32_to_fields(bytes: [u8;32]) -> [Field; 2] {
    let mut firstHalf: Field = 0x0;
    let mut lastHalf: Field = 0x0;

    let mut offset = 1;
    for i in 1..17 {
        firstHalf = firstHalf.add((bytes[16-i] as Field).mul(offset));
        lastHalf = lastHalf.add((bytes[32-i] as Field).mul(offset));
        offset *= 256;
    }
    [firstHalf, lastHalf]
}

#[test]
fn test_poseidon_2() {
    let preimage12 = [1, 2];
    let hashFixed2 = poseidon::bn254::hash_2(preimage12);
    assert(hashFixed2 == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a);
    //matches  HashFixed([]*big.Int{1, 2})
    //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L41  
}

#[test]
fn test_hash_2_with_domain() {
    let preimage12 = [1, 2];
    //HashFixedWithDomain([]*big.Int{b1, b2}, big.NewInt(256))
    //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L99
    let mut hashFixedDomain = hash_2_with_domain(256, preimage12);
    assert(hashFixedDomain == 0x05390df727dcce2ddb8faa3acb4798ad4e95b74de05e5cc7e40496658913ae85);
}

#[test]
fn test_node_hash() {
    // inputs as in proof
    // 0x0611d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040

    // inputs decoded
    // 0x06
    // 11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe
    // 082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040
    let node_type = 0x06;
    let left_child = 0x11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe;
    let right_child = 0x082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040;
    let node_hash = hash_2_with_domain(node_type, [left_child, right_child]);
    assert(node_hash == 0x084a2eb35e4cfd22b840cebde52db3567f0d46b99f69378a6d36361f367153ca, "node hash doesnt match");
}


#[test]
fn test_storage_leaf_hash() {    
    // leaf as in proof
    // 0x04108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a0101000000000000000000000000000000000000000000000000000000900661d8af4c8620dd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff
    
    // leafNode decoded
    // 0x04                                                             // leafNode type             1  byte
    // 108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a // node key                  32 byte            
    // 01010000                                                         // compressed flag array     4  bytes long
    // 00000000000000000000000000000000000000000000000000900661d8af4c86 // value                     32 byte   
    // 20                                                               // preImageSize = 32 bit     1  byte   
    // dd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff // storage key               32 bye
    

    //----------------------inputs-------------------

    // 0x4402c128c2337d7a6c4c867be68f7714a4e06429 = address in mapping lookup on erc balance
    // value = ethers.toBeArray("0x4402c128c2337d7a6c4c867be68f7714a4e06429")
    // zeros = Array(32 - value.length).fill(0);
    // [...zeros, ...value]
    let key: [u8] = [0,0,0,0,0,0,0,0,0,0,0,0,68,2,193,40,194,51,125,122,108,76,134,123,230,143,119,20,164,224,100,41]; 

    // value = ethers.toBeArray("0x00")
    // zeros = Array(32 - value.length).fill(0);
    // [...zeros, ...value]
    let slot: [u8] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];


    // value_preimage_bytes = balance of the address in the lookup (0x4402c128c2337d7a6c4c867be68f7714a4e06429)
    let value_preimage_bytes: [[u8;32]] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,144,6,97,216,175,76,134]];

    // node_type
    let leaf_node_type:Field = 0x04;

    //------------------------------------------------


    //-----------------hashing----------------------------

    // storage_key
    // node key preImage Hashing. NodeKeyPreImage = storageProof.key
    //0xdd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff
    let storage_key_preImg: [u8; 64] = key.append(slot).as_array();
    let storage_key_bytes = std::hash::keccak256(storage_key_preImg,64);

    // node_key
    let storage_key_split:[Field;2] = split_byte32_to_fields(storage_key_bytes);
    let node_key = hash_2_with_domain(512, storage_key_split);

    //Value Hash
    let value_preImg_split:[Field;2] = split_byte32_to_fields(value_preimage_bytes[0]);
    let value_hash = hash_2_with_domain(512, value_preImg_split);
    
    //node_hash
    let node_hash = hash_2_with_domain(leaf_node_type,[node_key, value_hash]);

    //--------------------------------------------------------------------

    assert(node_hash == 0x11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe,  "node_hash doesnt match");

}

#[test]
fn test_account_leaf_hash() {  
    //assert(false, "not implemented");
    //leaf as in proof 0x0420e9fb498ff9c35246d527da24aa1710d2cc9b055ecf9a95a8a2a11d3d836cdf050800000000000000000000000000000000000000000000000016ef00000000000000000000000000000000000000000000000000000000000001395d857ace5efb1c6e098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51e8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be205300000000000000000000000000000000000004000000000000000000000000

    // account leaf decoded
    // 0x04                                                             // node type
    // 20e9fb498ff9c35246d527da24aa1710d2cc9b055ecf9a95a8a2a11d3d836cdf // node key
    // 05080000                                                         // compressed flag array
    // 00000000000000000000000000000000                                 // reserved 16 bytes of zeros (32 zeros)
    // 00000000000016ef                                                 // codesize 8 bytes
    // 0000000000000000                                                 // nonce 8 bytes
    // 0000000000000000000000000000000000000000000001395d857ace5efb1c6e // balance padded 32 byte
    // 098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51 // storageRoot
    // e8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14 // keccakCodeHash
    // 136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be // poseidonCodeHash
    // 20                                                               // preImageSize = 32 bit     1  byte 
    // 5300000000000000000000000000000000000004000000000000000000000000 // contract address padded left 32 byte                                                           // means key preImg not availible
    

    // 0x5300000000000000000000000000000000000004 = the contract address =  the account in the account proof
    // padded with *trailing* zeros
    // value = ethers.toBeArray("0x5300000000000000000000000000000000000004")
    // zeros = Array(32 - value.length).fill(0);
    // [...value, ...zeros]
    let key_pre_image = [83,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0];
    let node_key = hash_2_with_domain(512, split_byte32_to_fields(key_pre_image));
    // TODO docs is wrong here its domain is 512
    // https://docs.scroll.io/en/technology/sequencer/zktrie/#ethereum-account-leaf-node
    assert(node_key == 0x20e9fb498ff9c35246d527da24aa1710d2cc9b055ecf9a95a8a2a11d3d836cdf, "node key doesn match");
    let node_type = 0x04;

    // https://docs.scroll.io/en/technology/sequencer/zktrie/#leaf-node
    // domain := 256 * 5  // 5 elements to compute the valueHash
    // valueHash :=
    //     h{domain}(
    //         h{domain}(
    //             h{domain}(nonce||codesize||0, balance),
    //             h{domain}(
    //                 storageRoot,
    //                 compressedKeccakCodeHash,
    //             ),
    //         ),
    //         poseidonCodeHash,
    //     )

    //0xe8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14.to_be_bytes(32).as_array(); <- doesnt work becuase fields are smaller then 32 byte
    let keccakCodeHash: [u8;32] =  [232,196,7,51,81,194,107,152,49,193,229,175,21,59,155,228,113,58,74,249,237,253,243,43,88,7,123,115,94,18,15,20];
    let nonce_codesize_0: Field = 0x0000000000000000000000000000000000000000000016ef0000000000000000; //hash_2_with_domain(512,split_byte32_to_fields(node_value_preimage[0]));
    let balance: Field = 0x0000000000000000000000000000000000000000000001395d857ace5efb1c6e; //hash_2_with_domain(512,split_byte32_to_fields(node_value_preimage[1]));
    let storageRoot: Field = 0x098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51; //hash_2_with_domain(512,split_byte32_to_fields(node_value_preimage[2]));
    let compressedKeccakCodeHash: Field = hash_2_with_domain(512,split_byte32_to_fields(keccakCodeHash));
    let poseidonCodeHash: Field = 0x136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be; //hash_2_with_domain(512,split_byte32_to_fields(node_value_preimage[4]));
    let domain:Field = 256 * 5;
    let value_hash: Field = 
        hash_2_with_domain(domain, [
            hash_2_with_domain(domain, [

                hash_2_with_domain(domain, [(nonce_codesize_0), (balance)]),

                hash_2_with_domain(domain, [
                    (storageRoot),
                    (compressedKeccakCodeHash)
                    ])
            ]),

            (poseidonCodeHash)
        ]);
        

    println(value_hash);
    let node_hash = hash_2_with_domain(node_type, [node_key, value_hash]);
    assert(node_hash == 0x1773e4a9875437b5692acfc4caf46b4db0666b1d98af4dd58fe2d03b6e20f4bb,"node_hash doesnt match" );
}

