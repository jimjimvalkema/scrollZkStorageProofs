use dep::std::hash::{keccak256};
use dep::std::hash::poseidon::bn254::hash_2;

// types
use dep::ScrollStorageProver::{Hash_path_proof,Hash_paths_state_proof,Account_preimage_excl_storage};

// formatting
use dep::ScrollStorageProver::{split_byte32_to_fields,bytes32_to_field, get_state_root};

// hashing
use dep::ScrollStorageProver::{
    mapping_slot_to_blockhash,
    compute_merkle_root,
    hash_storage_leaf,
    hash_account_leaf,
    hash_node_key_from_mapping,
    poseidon2_domain
};

//WARNING should be 254 but set to 25 to make test easier to change and read
global MAX_TREE_DEPTH: u32 = 26;
global MAX_BYTES_BLOCK_HASH_PREIMAGE: u32 = 680; //should be enough scroll mainnet wasn't going above 621, my guess is 673 bytes max + rlp over head. idk what overhead is tho.
global HASH_DOMAIN_BYTE32: Field = 512;

#[test]
fn test_poseidon_2() {
    let preimage12 = [1, 2];
    let hashFixed2 = hash_2(preimage12);
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
    let node_key: Field = hash_node_key_from_mapping(key, slot);
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
    // 136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be // poseidon_code_hash
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


    //0xe8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14.to_be_bytes(32).as_array(); <- doesnt work because fields are smaller then 32 byte
    let keccakCodeHash: [u8;32] =  [232,196,7,51,81,194,107,152,49,193,229,175,21,59,155,228,113,58,74,249,237,253,243,43,88,7,123,115,94,18,15,20];
    let nonce_codesize_0: Field = 0x0000000000000000000000000000000000000000000016ef0000000000000000; //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[0]));
    let balance: Field = 0x0000000000000000000000000000000000000000000001395d857ace5efb1c6e; //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[1]));
    let storageRoot: Field = 0x098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51; //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[2]));
    let poseidon_code_hash: Field = 0x136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be; //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[4]));

    // pre prosses inputs
    let compressed_keccak_code_hash: Field = poseidon2_domain(HASH_DOMAIN_BYTE32,split_byte32_to_fields(keccakCodeHash));

    let node_key = poseidon2_domain(HASH_DOMAIN_BYTE32, split_byte32_to_fields(key_pre_image));
    let node_hash = hash_account_leaf(node_key,nonce_codesize_0, balance, storageRoot,  compressed_keccak_code_hash,poseidon_code_hash,node_type);
    assert(node_hash == 0x1773e4a9875437b5692acfc4caf46b4db0666b1d98af4dd58fe2d03b6e20f4bb,"node_hash doesnt match" );
}

#[test]
fn test_compute_merkle_root_storage_proof() {
    let leaf_hash: Field = 0x11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe;
    //let node_key: Field = 0x108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a;
    let hash_path: [Field; MAX_TREE_DEPTH] = [0x082fd83e1176c02bba56005b3ba042af371971b4716f243642fca2a35a975040,0x0000000000000000000000000000000000000000000000000000000000000000,0x0000000000000000000000000000000000000000000000000000000000000000,0x1dbb1b961bc57d29f8b809aea22725896f8fe0054b90fb1a0f20ef8ce6b348e5,0x2cbc648029cf765385f6a17be45bbe74628c15d4c08f8d5e3f4491d94ae177e3,0x1eaff424e9893b368db781d66aee078fa2e932a269c009b6951586a5063bb3fb,0x2fde6d7e33e7c0dbf7448021a23e1b9f861de9906be91401e32987c506fa0a38,0x2acc21883e7d177c905ca2431c11fed214eebeaf95bb5bb3ff18b6988bcd2f6c,0x064fe3c43019c279d94c50619936c695080152678ca4448656e54790b124ba10,0x0e3a034343d14f2e9fa79bc58f3c5e83212ab34ad4216494ce5d0ba69a24129f,0x1e01222677655045108f8adabfb6b5aae23d15b6e8b865b885d22677930b1327,0x279df33aa48b973b0c4711959ba4032c91115266da7d46aa1eef4d5b4df50529,0x2c516cd8168873553bf5613fa108cf158db9f77356a14e5999a089bcb30bcc0d,0x169c51364a1a5d0d2fdf569654fdbb01f0fc57ce96f51224ace6c2b122a278f2,0x17ddf467aa6ad4be84637262c8bde743f303851b55a90cecaeb62f20949dd26a,0x0d0f3ad20d01ebbc06dddc8a4a4969088c6306a59e0941d09c608b86cddedf50,0x2704a07ac2ab2eef36c79b8e22eb2ebc49dfe7417500b04aac96b6f3babb802c,0x1dd281308230419c26bcd28b8ed40c561922c8c881e552f76c6575d16863e5ec,0x13a303bbb1e8cf20f48dd19ae218fda161c83fa10a7915615f0cc7028be36e4d,0x1590f4aaba59ff46a09d7a6a152cbf27280c2fbaa4bb94aa3eefab3bbd7d6e19,0x0,0x0,0x0,0x0,0x0,0x0];
    let node_types: [Field; MAX_TREE_DEPTH] = [6,7,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0,0,0,0,0];
    // @notice real_hash_path_len is there because the haspath is often shorter than the full tree depth. 
    // However we still need our arrays to be the full length since dynamic array sizes arnt allowed as inputs on a main function. 
    // after index of real_hash_path_len all the values are set to 0
    let real_hash_path_len: u32 = 20;
    let hash_path_bools: [bool;MAX_TREE_DEPTH] = [false,true,false,true,true,false,false,false,true,true,true,false,false,false,false,false,true,false,true,false,false,false,false,false,false,false];
    
    let computed_root:Field = compute_merkle_root(leaf_hash, hash_path, node_types, real_hash_path_len, hash_path_bools);
    let storage_root:Field = 0x098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51;
    assert(computed_root == storage_root, "computed_root doesnt match storage root");
}

#[test]
fn test_compute_merkle_root_account_proof() {
    let leaf_hash: Field = 0x1773e4a9875437b5692acfc4caf46b4db0666b1d98af4dd58fe2d03b6e20f4bb;
    //let node_key: Field = 0x20e9fb498ff9c35246d527da24aa1710d2cc9b055ecf9a95a8a2a11d3d836cdf;
    let hash_path: [Field; MAX_TREE_DEPTH] = [0x21fb69ccdb00e6eaeaf7fc1e73630f39f846970b72ac801e396da0033fb0c247,0x1509aaaacf0678c3da394ea3edc21dc3c48767a85544a8f435b69f87ddfbaf0a,0x2fc2e33fdb53f97cdfc63e66de1e6a497a98b8d109c4f88a1eea4881f0929526,0x09ba87b2bd7facc2a4c986d82a5cb4001468843a60063c78a8d250b56f448377,0x160bcff072cec6d5f61ed69d2ed26cf539ae10655dd8a5a625ddf933ca1a42e4,0x0f7f936cd304525d85e1b33fedc1f62b9bfd87030ffb7b843eacd445fc4aea7f,0x242415f663834078570a91f27e9a1bcee2d0c0a0936c1010fe0d92c8ea935a18,0x2c342e07f95e2472f32bf2637467f30a2343e3f4fc702ac088c7e196d4de708b,0x134c58331016b26e8e3eedd0955eb8a54dab8e290ea9b957f4713cc79be917a6,0x0258b45271d86dfd4706c256753a684f08a05d258a5fff6750b0e2fd32e1cf4d,0x13c97981b6360a26dbe4f4694175d1d9a0e248ba734bf9e9e4d57df3c53f2437,0x1c41fc3e5ece5c5d2ccb67595d3a89fb39d43b32827f0464dd6aeb8f1a9ca701,0x0466fc11eb066d337c51cf870f18084e95000e890245833bcb16a134a22c4723,0x149966c5c9cb6966c568fb099c5385b0b4831be1f29f3592833749fb15bf405d,0x2309d7599612bb43f1bb17e40747eef76c254d444daaae064052edd1972f4440,0x20641a9afc11694b5a8c8acec09dc9f70a75fbc7914d1f5e9a41f15cd00665ae,0x2f98ca34e139c1057f0a30611814d34de4d80813497d7c9c863e697c95aa3cb5,0x0dc44be05703a33acb8c11756ad727c227fd086c46469a26a7a9d6750f439616,0x269ae40a8f39ab073983fb6fe0e384a865bcc21ec6e09e307fcc8692a6151ebc,0x0e8692bbc1d31269263cef16273badc1aebc37f1047bcd03c117a82c5b878610,0x2ad53eebc0132ed6cefb20cb9bb3379d8e7aa0b14d83663dc508aa16607a5efb,0x0e22fafbcae714df93561f55ce0ec547c98ae23e0f58a0e4cd5fe157edca1c4f,0x1a405dfd689829d259c07d7962144343a2052edd73d8d805958c107d31d54860, 0x0,0x0,0x0];
    let node_types: [Field; MAX_TREE_DEPTH] = [6,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,0,0,0];
    let hash_path_bools: [bool; MAX_TREE_DEPTH] = [false,false,false,false,false,true,true,false,true,true,false,true,true,false,false,true,true,false,true,true,true,true,true,false,false,false];
    let real_hash_path_len = 23;

    let computed_root:Field = compute_merkle_root(leaf_hash, hash_path, node_types, real_hash_path_len, hash_path_bools);
    let state_root:Field = 0x166065fc76a540ec1ec944e4a8e409c8d9615b77621504efff154e0132f8e8f8;
    assert(computed_root == state_root, "computed_root doesnt match storage root");
}


#[test]
fn test_get_state_root() {
    let header_rlp:[u8;MAX_BYTES_BLOCK_HASH_PREIMAGE] = [249,2,92,160,239,37,169,176,180,227,63,164,8,23,74,123,2,50,96,72,192,223,169,179,175,31,225,216,123,74,73,232,114,130,59,90,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,22,96,101,252,118,165,64,236,30,201,68,228,168,228,9,200,217,97,91,119,98,21,4,239,255,21,78,1,50,248,232,248,160,136,102,42,69,64,99,89,76,135,191,116,65,216,161,127,113,49,212,190,59,37,30,139,65,60,85,44,161,45,226,246,216,160,158,25,2,237,43,125,57,186,32,212,200,246,195,128,119,200,198,67,196,165,185,217,54,244,106,106,21,249,173,46,18,143,185,1,0,0,2,16,0,4,0,0,64,0,0,32,0,0,128,64,32,0,4,0,0,34,0,32,16,8,16,18,0,0,80,1,1,5,16,0,0,32,2,8,0,16,0,128,0,0,0,0,0,0,0,64,0,0,32,2,4,0,0,0,4,0,32,0,0,0,0,128,0,4,112,32,0,2,0,0,8,0,0,0,0,0,0,8,16,0,0,0,0,160,1,0,0,0,0,0,8,0,0,0,0,66,16,0,16,0,0,4,0,0,0,8,8,0,0,0,64,32,16,64,0,0,0,0,16,0,0,2,0,0,1,4,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,64,0,0,0,8,129,128,0,0,0,0,7,65,2,64,130,0,0,1,32,0,64,0,16,0,0,0,0,0,32,0,2,0,32,64,0,16,0,0,0,0,0,0,0,32,32,0,0,34,0,0,0,32,0,0,128,2,1,0,64,0,0,20,0,0,32,0,0,8,0,0,0,16,0,0,32,0,128,16,0,132,0,0,0,2,0,0,4,0,0,2,4,0,0,0,0,32,17,0,128,0,0,0,32,0,12,0,0,0,2,131,98,190,31,131,152,150,128,131,14,199,206,132,102,104,97,14,184,97,216,131,5,3,32,132,103,101,116,104,136,103,111,49,46,50,48,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,98,35,151,26,49,19,62,111,213,69,22,123,70,156,179,46,68,8,66,169,246,237,189,150,167,155,212,142,202,153,105,118,50,142,15,6,182,252,51,82,55,245,167,10,219,154,87,83,247,147,198,131,202,118,201,93,24,196,4,87,170,156,181,215,1,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    //let real_header_rlp_len = 607;
    let state_root:Field = 0x166065fc76a540ec1ec944e4a8e409c8d9615b77621504efff154e0132f8e8f8;

    let state_root_rlp = get_state_root(header_rlp);
    assert(bytes32_to_field(state_root_rlp) == state_root, "state root doesnt match. Did the header layout change?");
}


#[test]
fn test_mapping_slot_to_blockhash() {
    // input
    let user_address: [u8;32]       = [0,0,0,0,0,0,0,0,0,0,0,0,39,58,159,166,247,117,29,181,190,76,28,173,204,11,107,213,201,99,231,229];         // 0x273a9fa6f7751db5be4c1cadcc0b6bd5c963e7e5
    let slot: [u8; 32]              = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];                                     // slot = 0
    let user_balance:  [u8; 32]     = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,22,196,171,190,190,160,16,0,0];                         // 420.000
    let padded_contract: [u8;32]    = [33,208,131,41,94,37,81,229,129,92,47,11,76,183,61,226,83,145,6,183,0,0,0,0,0,0,0,0,0,0,0,0];          // 0x21d083295e2551e5815c2f0b4cb73de2539106b7 zkwormholes on scroll sepolia 

    // proof data
    let storage_proof: Hash_path_proof<23> = Hash_path_proof {
        hash_path:  [0x271dcf322b72eadde439e5f2fe303af0d6ab3fa6c79a9466704a4791f85af7b3,0x0000000000000000000000000000000000000000000000000000000000000000,0x2bff2dd5919b91b80722debba0da0ba15eb2ac950ba965c07cde492494242177,0x29e2f4c47f71ee542e6ab5571f0eda8230b57f3166178244ea0603655ec82ddb,0x037babdabb3dd50298f663dcfb1124a68a0f2b80dcd4a949f797a188e6c93964,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        node_types: [7,8,9,9,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        leaf_type:  0x04,
        real_hash_path_len: 5,
        hash_path_bools:  [false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false],
    };

    let account_proof: Hash_path_proof<23> =  Hash_path_proof {
        hash_path:  [0x0b2247fce447f1671dd6d174be45b074fd89a6330b08ab2c87496dee6f03115e,0x0000000000000000000000000000000000000000000000000000000000000000,0x2614c322fa1f971ce06d0c8fc2ab71bd13aac9e3a1bed9a69079a751275090e6,0x0103d17039f4bfb2134f878fddb08dc0f9919cc8177f195e2c21fd036d70e4d8,0x0bd0af6c5f4ac2609f47db7358b32af8707d9b1f1ea8816c43aaf088420c2a82,0x1876a6e0855526abd8bcbf767b7a467eadd99f56e18e89cc8f18e8d523621e65,0x17837b58b18c4fe6f293bb55920a56bf1733a70feed305e4ee807739d594d3b7,0x1e89d0ca62cf848177514f72239d630fc57864865dc889f656595d0dedcfe03c,0x24f5e254afbd2370fe36aab6d1a03f93c48f29a9cc60f56275a4a530f64f898f,0x245536539214afb67ba8c93f6f8bb5052b4d6c83468cfec754d137ae1cc7cec2,0x27ebaf0af037f48257d57cbfba74c0a006558633204390caacf3db1d5c65b07e,0x28f5020177be2ed30dddd260de462f2579c2d4bb122155124101bb8acf219a94,0x16a327dc5939dfd27bd90050baf91ee38546f140503161a0a754024837e09bb3,0x2d9d973280548b9501fbc42e50d14c6c09ed30087dbed6583edc5f72f9c9e3b3,0x1e38ae00c9d40824a4c6ea5c837a892ae1370c1ddb0b2f69f2334d67bdb4b1df,0x10fb06ec6d590d63efd1df5fee4e45e895c6c1e7d7c919522da0ed385139563f,0x1301413522e53da157c1757272fa2f1541b42d74eb6c010233b5f0e87ec40ed0,0x094cb1ae53b96f40b137c2dc5b659d6de3aae90e8f897882528dc509fef9acdf,0x2634dfe5f14fee94cd389e331c5a4492f50806970c524b2e56279de1bed5d93f,0x05d288c9cd54ee7b9cb7e1f1ae7e1ba224bc84462f6896af1672611c1a312014,0x1cdea36b73ebeb92696b6d7742cf491a3c80eb928170b995c3b36c82038535fb,0x16b46259455ce43f114a34d3b2e443994e4930aa944372351536d0c4f49c3ec1,0x14ccc4fe67292c6bf607664f80b0d4963e3ec3499178d736e2bad1b0626c6bee],
        node_types: [6,7,8,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],
        leaf_type:  0x04,
        real_hash_path_len: 23,
        hash_path_bools: [false,true,false,false,true,true,true,false,true,true,true,false,false,true,false,false,true,false,false,true,false,false,true],
    };

    //from:
    // node ./scripts/fetchStorageProof.js --mappingMode --contractAddress=0x21d083295e2551e5815c2f0b4cb73de2539106b7 --key=0x273a9fa6f7751db5be4c1cadcc0b6bd5c963e7e5 --slot=0x00 --keyType=address --provider=https://sepolia-rpc.scroll.io
    let keccakCodeHash: [u8;32] =  [81,86,129,95,249,230,11,255,151,231,149,233,40,61,210,10,71,202,57,165,100,112,68,213,1,23,130,139,211,72,73,242];
    let account_preimage = Account_preimage_excl_storage {
        nonce_codesize_0:   0x0000000000000000000000000000000000000000000010140000000000000001,  //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[0]));
        balance:            0x0000000000000000000000000000000000000000000000000000000000000000,             //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[1]));
        //storageRoot:0x098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51,         //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[2]));
        compressed_keccak_code_hash: poseidon2_domain(HASH_DOMAIN_BYTE32,split_byte32_to_fields(keccakCodeHash)),
        poseidon_code_hash: 0x0e630c824b73bb5c6321b6342d9f22ae2deeb567cd23d85a80ff0dbeff4ec533, //poseidon2_domain(512,split_byte32_to_fields(node_value_preimage[4]));
    };

    let header_rlp:[u8;MAX_BYTES_BLOCK_HASH_PREIMAGE] = [249,2,96,160,163,70,1,115,111,44,209,25,220,10,0,137,30,102,152,63,255,188,83,2,219,56,72,25,8,55,82,16,185,69,41,21,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,9,38,193,3,56,5,151,175,35,243,38,34,84,243,253,248,51,18,239,166,202,92,186,98,171,153,41,75,31,0,235,193,160,253,148,252,193,46,3,213,157,166,1,195,2,41,39,38,214,181,92,15,240,204,195,21,108,137,70,70,41,186,149,234,242,160,17,55,158,130,75,112,246,28,120,22,41,103,240,203,75,132,245,246,232,132,198,126,87,214,235,253,247,181,243,214,156,89,185,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,0,0,2,131,121,116,229,131,152,150,128,130,150,126,132,103,144,254,187,184,97,216,131,5,8,0,132,103,101,116,104,136,103,111,49,46,50,49,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,156,57,27,94,45,143,46,3,10,133,208,207,150,42,11,237,119,3,194,218,11,192,27,44,62,136,106,253,36,120,128,184,28,160,172,40,196,253,196,95,191,8,169,91,24,173,174,54,24,225,40,65,240,89,254,76,19,165,166,58,232,138,40,4,1,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0,132,2,138,204,21,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let header_rlp_len = 611;
    // let state_root_rlp = get_state_root(header_rlp);
    // println(state_root_rlp);

    let block_hash:[u8;32] = mapping_slot_to_blockhash(
        user_address, 
        slot, 
        user_balance, 
        padded_contract, 
        account_proof,
        storage_proof, 
        account_preimage,
        header_rlp,
        header_rlp_len
    );
    //0x805f76c5a44e447909bf8d449b409415afa02dd145def3524ec4bf08a9d2e149
    println(block_hash);
    assert(block_hash == [64,96,238,243,181,165,242,135,2,116,176,48,232,216,60,105,210,242,19,254,77,27,216,65,234,155,226,144,127,121,201,93], "block hash didnt match");



    // // proving
    // let computed_state_root = mapping_slot_to_blockhash(user_address, slot, user_balance, padded_contract, hash_paths, account_preimage);
    // let state_root = 0x166065fc76a540ec1ec944e4a8e409c8d9615b77621504efff154e0132f8e8f8;
    // assert(computed_state_root == state_root, "computed_root doesnt match storage root");

    // assert(bytes32_to_field(state_root_rlp) == computed_state_root, "state root doesnt match. Did the header layout change?");
}

// related to a bug in noir 0.33.0 and 0.34.0
#[test]
fn keccak_135_input() {
    let input:[u8;135]  = [69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69];
    let out:[u8;32] = keccak256(input,input.len());
    assert(out != [0;32]);
}

#[test]
fn keccak_136_input() {
    let input:[u8;136]  = [69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69,69];
    let out:[u8;32] = keccak256(input,input.len());
    assert(out != [0;32]);
}

// keccak is broken in 0.33.0 cant do > 136 len
// https://github.com/noir-lang/noir/blob/999071b80e61a37cb994a4e359eabbac27cd53f1/noir_stdlib/src/hash/keccak.nr#L16C8-L16C24
#[test]
fn test_block_hash() {
    // added 3 zeros as test.  those zeros are ignored becaues keccak256 uses 607 as lenght arg
    let header_rlp:[u8;MAX_BYTES_BLOCK_HASH_PREIMAGE] = [249,2,92,160,239,37,169,176,180,227,63,164,8,23,74,123,2,50,96,72,192,223,169,179,175,31,225,216,123,74,73,232,114,130,59,90,160,29,204,77,232,222,199,93,122,171,133,181,103,182,204,212,26,211,18,69,27,148,138,116,19,240,161,66,253,64,212,147,71,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,160,22,96,101,252,118,165,64,236,30,201,68,228,168,228,9,200,217,97,91,119,98,21,4,239,255,21,78,1,50,248,232,248,160,136,102,42,69,64,99,89,76,135,191,116,65,216,161,127,113,49,212,190,59,37,30,139,65,60,85,44,161,45,226,246,216,160,158,25,2,237,43,125,57,186,32,212,200,246,195,128,119,200,198,67,196,165,185,217,54,244,106,106,21,249,173,46,18,143,185,1,0,0,2,16,0,4,0,0,64,0,0,32,0,0,128,64,32,0,4,0,0,34,0,32,16,8,16,18,0,0,80,1,1,5,16,0,0,32,2,8,0,16,0,128,0,0,0,0,0,0,0,64,0,0,32,2,4,0,0,0,4,0,32,0,0,0,0,128,0,4,112,32,0,2,0,0,8,0,0,0,0,0,0,8,16,0,0,0,0,160,1,0,0,0,0,0,8,0,0,0,0,66,16,0,16,0,0,4,0,0,0,8,8,0,0,0,64,32,16,64,0,0,0,0,16,0,0,2,0,0,1,4,0,0,0,0,0,128,0,0,0,0,0,0,0,0,0,0,64,0,0,0,8,129,128,0,0,0,0,7,65,2,64,130,0,0,1,32,0,64,0,16,0,0,0,0,0,32,0,2,0,32,64,0,16,0,0,0,0,0,0,0,32,32,0,0,34,0,0,0,32,0,0,128,2,1,0,64,0,0,20,0,0,32,0,0,8,0,0,0,16,0,0,32,0,128,16,0,132,0,0,0,2,0,0,4,0,0,2,4,0,0,0,0,32,17,0,128,0,0,0,32,0,12,0,0,0,2,131,98,190,31,131,152,150,128,131,14,199,206,132,102,104,97,14,184,97,216,131,5,3,32,132,103,101,116,104,136,103,111,49,46,50,48,46,49,133,108,105,110,117,120,0,0,0,0,0,0,0,98,35,151,26,49,19,62,111,213,69,22,123,70,156,179,46,68,8,66,169,246,237,189,150,167,155,212,142,202,153,105,118,50,142,15,6,182,252,51,82,55,245,167,10,219,154,87,83,247,147,198,131,202,118,201,93,24,196,4,87,170,156,181,215,1,160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let real_header_rlp_len = 607;
    let block_hash:[u8;32] = [128,95,118,197,164,78,68,121,9,191,141,68,155,64,148,21,175,160,45,209,69,222,243,82,78,196,191,8,169,210,225,73];
    let computed_block_hash = keccak256(header_rlp,real_header_rlp_len);
    assert(computed_block_hash == block_hash, "block hash doesn match");
}
