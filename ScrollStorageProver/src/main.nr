use dep::std;
use dep::std::hash::poseidon;
use dep::std::hash::poseidon::bn254::perm;

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/hash.go#L16
global HASH_DOMAIN_ELEMS_BASE:Field = 256; // TODO maybe change to u8 ??
global HASH_DOMAIN_BYTE32:Field     = 2 * HASH_DOMAIN_ELEMS_BASE;
global ACCOUNT_LEAF_VALUE_PREIMAGE_LEN =  5;
global HASH_DOMAIN_ACCOUNT_LEAF:Field = 5 * HASH_DOMAIN_ELEMS_BASE;

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

// used hash_2 from noirs std as example
// https://github.com/noir-lang/noir/blob/8a322998ee60875f7abe4dc222f8fdc20cb0ee0a/noir_stdlib/src/hash/poseidon/bn254.nr#L24
// and from the go-ethereum scroll repo
// https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon.go#L157
pub fn poseidon2_domain(domain: Field, input: [Field; 2]) -> Field {
    let mut state = [0; 3];
    state[0] = domain;
    for i in 0..input.len() {
        state[i+1] = input[i];
    }
    perm::x5_3(state)[0]
}

// used merkle from noir std as example
// https://github.com/noir-lang/noir/blob/49e1b0c0d45565f3e87469b77f2fef0c283f6ea1/noir_stdlib/src/merkle.nr#L5
// Returns the merkle root of the tree from the provided leaf, its hashpath, domains, using a poseidon2 with the domain argument
pub fn compute_merkle_root<N>(leaf_hash: Field, node_key: Field, hash_path: [Field; N], node_types: [Field; N]) -> Field {
    let n = hash_path.len();
    // TODO  node_key.to_be_bits can be done outside of the circuit. see if thats better
    let node_key_bits = node_key.to_be_bits(n as u32);
    let mut current = leaf_hash;
    for i in 0..n {
        let path_bit = node_key_bits[i] as bool;
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };
        let domain = node_types[i];
        current = poseidon2_domain(domain,[hash_left, hash_right]);
    }
    current
}



pub fn hash_storage_leaf_node_key(key: [u8; 32], slot: [u8; 32]) -> Field {
    // node key preImage Hashing. NodeKeyPreImage = storageProof.key
    //0xdd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff
    let storage_key_preImg: [u8; 64] = key.as_slice().append(slot.as_slice()).as_array();
    let storage_key_bytes = std::hash::keccak256(storage_key_preImg,64);

    // node_key
    // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/util.go#L107
    let storage_key_split:[Field;2] = split_byte32_to_fields(storage_key_bytes);
    poseidon2_domain(HASH_DOMAIN_BYTE32, storage_key_split)
}

pub fn hash_storage_leaf(node_key: Field, value_preimage: [u8; 32], leaf_node_type: Field) -> Field {
    //Value Hash
    let value_preImg_split:[Field;2] = split_byte32_to_fields(value_preimage);
    let value_hash = poseidon2_domain(HASH_DOMAIN_BYTE32, value_preImg_split);
    
    //node_hash
    poseidon2_domain(leaf_node_type,[node_key, value_hash])
}

pub fn hash_account_leaf(
    node_key: Field,
    nonce_codesize_0: Field, 
    balance: Field, 
    storageRoot: Field,  
    compressedKeccakCodeHash: Field,
    poseidonCodeHash: Field,
    node_type: Field
    ) -> Field {
    // docs is wrong here its domain is 512
    // https://github.com/scroll-tech/scroll-documentation/issues/281
    // https://docs.scroll.io/en/technology/sequencer/zktrie/#ethereum-account-leaf-node


    // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/util.go#L10
    // https://docs.scroll.io/en/technology/sequencer/zktrie/#leaf-node
    // domain := 256 * 5  // 5 elements to compute the valueHash
    //             value_hash
    //                 /\
    //                 |
    // h{domain}(_____, _____) 
    //             /        \
    //            /          \
    // poseidonCodeHash    h{domain}(_____, _____) 
    //                               /          \
    //                              /            \
    //                             /              \
    // h{domain}(nonce||codesize||0, balance)  h{domain}(storageRoot, compressedKeccakCodeHash)
    let value_hash: Field = 
        poseidon2_domain(HASH_DOMAIN_ACCOUNT_LEAF, [
            poseidon2_domain(HASH_DOMAIN_ACCOUNT_LEAF, [

                poseidon2_domain(HASH_DOMAIN_ACCOUNT_LEAF, [nonce_codesize_0, balance]),

                poseidon2_domain(HASH_DOMAIN_ACCOUNT_LEAF, [
                    storageRoot,
                    compressedKeccakCodeHash
                    ])
            ]),

            (poseidonCodeHash)
        ]);
        
    poseidon2_domain(node_type, [node_key, value_hash])

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
fn test_poseidon2_domain() {
    let preimage12 = [1, 2];
    //HashFixedWithDomain([]*big.Int{b1, b2}, big.NewInt(256))
    //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L99
    let mut hashFixedDomain = poseidon2_domain(256, preimage12);
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
    let node_hash = poseidon2_domain(node_type, [left_child, right_child]);
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
    let key: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,68,2,193,40,194,51,125,122,108,76,134,123,230,143,119,20,164,224,100,41]; 

    // value = ethers.toBeArray("0x00")
    // zeros = Array(32 - value.length).fill(0);
    // [...zeros, ...value]
    let slot: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];


    // value_preimage_bytes = balance of the address in the lookup (0x4402c128c2337d7a6c4c867be68f7714a4e06429)
    let value_preimage_bytes: [[u8;32]] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,144,6,97,216,175,76,134]];

    // node_type
    let leaf_node_type:Field = 0x04;

    //------------------------------------------------


    //-----------------hashing----------------------------
    let node_key: Field = hash_storage_leaf_node_key(key, slot);
    let node_hash = hash_storage_leaf(node_key,value_preimage_bytes[0],leaf_node_type);
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
    // e8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14 // keccakCodeHash // 0x0b76dac2b0a40ec033204a8924a316feab1261917f1807c68dca97310bf17edb
    // 136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be // poseidonCodeHash
    // 20                                                               // preImageSize = 32 bit     1  byte 
    // 5300000000000000000000000000000000000004000000000000000000000000 // contract address padded left 32 byte                                                           // means key preImg not availible
    

    // 0x5300000000000000000000000000000000000004 = the contract address =  the account in the account proof
    // padded with *trailing* zeros
    // value = ethers.toBeArray("0x5300000000000000000000000000000000000004")
    // zeros = Array(32 - value.length).fill(0);
    // [...value, ...zeros]
    // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/util.go#L107
    let key_pre_image = [83,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0];
    let node_type = 0x04;


    //0xe8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14.to_be_bytes(32).as_array(); <- doesnt work becuase fields are smaller then 32 byte
    let keccakCodeHash: [u8;32] =  [232,196,7,51,81,194,107,152,49,193,229,175,21,59,155,228,113,58,74,249,237,253,243,43,88,7,123,115,94,18,15,20];
    let nonce_codesize_0: Field = 0x0000000000000000000000000000000000000000000016ef0000000000000000; //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[0]));
    let balance: Field = 0x0000000000000000000000000000000000000000000001395d857ace5efb1c6e; //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[1]));
    let storageRoot: Field = 0x098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51; //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[2]));
    let poseidonCodeHash: Field = 0x136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be; //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[4]));

    // pre prosses inputs
    let compressedKeccakCodeHash: Field = poseidon2_domain(HASH_DOMAIN_BYTE32,split_byte32_to_fields(keccakCodeHash));

    let node_key = poseidon2_domain(HASH_DOMAIN_BYTE32, split_byte32_to_fields(key_pre_image));
    let node_hash = hash_account_leaf(node_key,nonce_codesize_0, balance, storageRoot,  compressedKeccakCodeHash,poseidonCodeHash,node_type);
    assert(node_hash == 0x1773e4a9875437b5692acfc4caf46b4db0666b1d98af4dd58fe2d03b6e20f4bb,"node_hash doesnt match" );
}

#[test]
fn test_compute_merkle_root_storage_proof() {
    let leaf_hash: Field = 0x11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe;
    let node_key: Field = 0x108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a;
    let hash_path = [0x082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040,0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000000,0x1dbb1b961bc57d29f8b809aea22725896f8fe0054b90fb1a0f20ef8ce6b348e5,0x2cbc648029cf765385f6a17be45bbe74628c15d4c08f8d5e3f4491d94ae177e3,0x1eaff424e9893b368db781d66aee078fa2e932a269c009b6951586a5063bb3fb,0x2fde6d7e33e7c0dbf7448021a23e1b9f861de9906be91401e32987c506fa0a38,0x2acc21883e7d177c905ca2431c11fed214eebeaf95bb5bb3ff18b6988bcd2f6c,0x064fe3c43019c279d94c50619936c695080152678ca4448656e54790b124ba10,0x0e3a034343d14f2e9fa79bc58f3c5e83212ab34ad4216494ce5d0ba69a24129f,0x1e01222677655045108f8adabfb6b5aae23d15b6e8b865b885d22677930b1327,0x279df33aa48b973b0c4711959ba4032c91115266da7d46aa1eef4d5b4df50529,0x2c516cd8168873553bf5613fa108cf158db9f77356a14e5999a089bcb30bcc0d,0x169c51364a1a5d0d2fdf569654fdbb01f0fc57ce96f51224ace6c2b122a278f2,0x17ddf467aa6ad4be84637262c8bde743f303851b55a90cecaeb62f20949dd26a,0x0d0f3ad20d01ebbc06dddc8a4a4969088c6306a59e0941d09c608b86cddedf50,0x2704a07ac2ab2eef36c79b8e22eb2ebc49dfe7417500b04aac96b6f3babb802c,0x1dd281308230419c26bcd28b8ed40c561922c8c881e552f76c6575d16863e5ec,0x13a303bbb1e8cf20f48dd19ae218fda161c83fa10a7915615f0cc7028be36e4d,0x1590f4aaba59ff46a09d7a6a152cbf27280c2fbaa4bb94aa3eefab3bbd7d6e19];
    let node_types = [6,7,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9];
    
    let computed_root:Field = compute_merkle_root(leaf_hash, node_key, hash_path, node_types);
    let storage_root:Field = 0x098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51;
    assert(computed_root == storage_root, "computed_root doesnt match storage root");
}

#[test]
fn test_compute_merkle_root_account_proof() {
    let leaf_hash: Field = 0x1773e4a9875437b5692acfc4caf46b4db0666b1d98af4dd58fe2d03b6e20f4bb;
    let node_key: Field = 0x20e9fb498ff9c35246d527da24aa1710d2cc9b055ecf9a95a8a2a11d3d836cdf;
    let hash_path = [0x21fb69ccdb00e6eaeaf7fc1e73630f39f846970b72ac801e396da0033fb0c247,0x1509aaaacf0678c3da394ea3edc21dc3c48767a85544a8f435b69f87ddfbaf0a,0x2fc2e33fdb53f97cdfc63e66de1e6a497a98b8d109c4f88a1eea4881f0929526,0x09ba87b2bd7facc2a4c986d82a5cb4001468843a60063c78a8d250b56f448377,0x160bcff072cec6d5f61ed69d2ed26cf539ae10655dd8a5a625ddf933ca1a42e4,0x0f7f936cd304525d85e1b33fedc1f62b9bfd87030ffb7b843eacd445fc4aea7f,0x242415f663834078570a91f27e9a1bcee2d0c0a0936c1010fe0d92c8ea935a18,0x2c342e07f95e2472f32bf2637467f30a2343e3f4fc702ac088c7e196d4de708b,0x134c58331016b26e8e3eedd0955eb8a54dab8e290ea9b957f4713cc79be917a6,0x0258b45271d86dfd4706c256753a684f08a05d258a5fff6750b0e2fd32e1cf4d,0x13c97981b6360a26dbe4f4694175d1d9a0e248ba734bf9e9e4d57df3c53f2437,0x1c41fc3e5ece5c5d2ccb67595d3a89fb39d43b32827f0464dd6aeb8f1a9ca701,0x0466fc11eb066d337c51cf870f18084e95000e890245833bcb16a134a22c4723,0x149966c5c9cb6966c568fb099c5385b0b4831be1f29f3592833749fb15bf405d,0x2309d7599612bb43f1bb17e40747eef76c254d444daaae064052edd1972f4440,0x20641a9afc11694b5a8c8acec09dc9f70a75fbc7914d1f5e9a41f15cd00665ae,0x2f98ca34e139c1057f0a30611814d34de4d80813497d7c9c863e697c95aa3cb5,0x0dc44be05703a33acb8c11756ad727c227fd086c46469a26a7a9d6750f439616,0x269ae40a8f39ab073983fb6fe0e384a865bcc21ec6e09e307fcc8692a6151ebc,0x0e8692bbc1d31269263cef16273badc1aebc37f1047bcd03c117a82c5b878610,0x2ad53eebc0132ed6cefb20cb9bb3379d8e7aa0b14d83663dc508aa16607a5efb,0x0e22fafbcae714df93561f55ce0ec547c98ae23e0f58a0e4cd5fe157edca1c4f,0x1a405dfd689829d259c07d7962144343a2052edd73d8d805958c107d31d54860];
    let node_types = [6,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9];
    
    let computed_root:Field = compute_merkle_root(leaf_hash, node_key, hash_path, node_types);
    let state_root:Field = 0x166065fc76a540ec1ec944e4a8e409c8d9615b77621504efff154e0132f8e8f8;
    assert(computed_root == state_root, "computed_root doesnt match storage root");
}
