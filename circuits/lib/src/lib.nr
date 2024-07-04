use dep::std::hash::keccak256;
//use dep::std::hash::poseidon::bn254::hash_2;
use dep::std::hash::poseidon::bn254::perm;
use dep::std::field::bytes32_to_field;

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/hash.go#L16
global HASH_DOMAIN_ELEMS_BASE:Field = 256; // TODO maybe change to u8 ??
global HASH_DOMAIN_BYTE32:Field     = 2 * HASH_DOMAIN_ELEMS_BASE;
global ACCOUNT_LEAF_VALUE_PREIMAGE_LEN =  5;
global HASH_DOMAIN_ACCOUNT_LEAF:Field = 5 * HASH_DOMAIN_ELEMS_BASE;

// WARNING can change after upgrades if it no longer the 4th item in the header 
// or if ParentHash, UncleHash, Coinbase byte lenght changes
// actually rlp decoding can be used but it would be computationally costly
global STATE_ROOT_BLOCK_HEADER_OFFSET = 91;

struct Hash_path_proof<N> {
        hash_path: [Field;N],
        node_types: [Field;N],
        leaf_type: Field,
        real_hash_path_len: u64,
        hash_path_bools: [bool;N]
    }

struct Hash_paths_state_proof<S,A> {
    storage_proof: Hash_path_proof<S>,
    account_proof: Hash_path_proof<A>
}


struct Account_preimage_excl_storage {
    nonce_codesize_0: Field,
    balance: Field,
    compressed_keccak_code_hash: Field,
    poseidon_code_hash: Field
    
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
pub fn compute_merkle_root<N>(leaf_hash: Field,hash_path: [Field; N], node_types: [Field; N], hash_path_len: u64, hash_path_bools: [bool; N]) -> Field {
    let n = hash_path.len();
    let mut current = leaf_hash;
    for i in 0..n {
        if(i<hash_path_len){
            // TODO double check this 
            let path_bit = hash_path_bools[i];
            let (hash_left, hash_right) = if path_bit {
                (hash_path[i], current)
            } else {
                (current, hash_path[i])
            };
            let domain = node_types[i];
            current = poseidon2_domain(domain,[hash_left, hash_right]);
        }
    }
    current
}



pub fn hash_node_key_from_mapping(key: [u8; 32], slot: [u8; 32]) -> Field {
    // node key preImage Hashing. NodeKeyPreImage = storageProof.key
    let storage_key_preImg: [u8; 64] = key.as_slice().append(slot.as_slice()).as_array();
    let storage_key_bytes = keccak256(storage_key_preImg,64);

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
    compressed_keccak_code_hash: Field,
    poseidon_code_hash: Field,
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
    // poseidon_code_hash    h{domain}(_____, _____) 
    //                                 /          \
    //                                /            \
    //                               /              \
    // h{domain}(nonce||codesize||0, balance)  h{domain}(storageRoot, compressed_keccak_code_hash)
    let value_hash: Field = 
        poseidon2_domain(HASH_DOMAIN_ACCOUNT_LEAF, [
            poseidon2_domain(HASH_DOMAIN_ACCOUNT_LEAF, [

                poseidon2_domain(HASH_DOMAIN_ACCOUNT_LEAF, [nonce_codesize_0, balance]),

                poseidon2_domain(HASH_DOMAIN_ACCOUNT_LEAF, [
                    storageRoot,
                    compressed_keccak_code_hash
                    ])
            ]),

            poseidon_code_hash
        ]);
        
    poseidon2_domain(node_type, [node_key, value_hash])

}

// A = account proof hash_path lenght
// S = storage proof hash_path lenght

// ex mapping of balances erc20
// key = user address
// slot = storage slot where the _balances map is stored
// value = user balance (padded zeros at start)
// padded_contract = the contract address but with zeros at the start *left*
// hash_paths and account_preimage is extra information needed to compute the proof
pub fn storage_proof_on_mapping<A,S>(
        key: [u8;32], 
        slot: [u8; 32], 
        value:  [u8; 32], 
        padded_contract: [u8;32], 
        hash_paths: Hash_paths_state_proof<A,S>, 
        account_preimage: Account_preimage_excl_storage
    ) -> Field {
    
    // -----get storage_root from storage proof------
    // leafhash
    let storage_node_key: Field = hash_node_key_from_mapping(key, slot);
    let storage_leaf_hash = hash_storage_leaf(
            storage_node_key,
            value,hash_paths.storage_proof.leaf_type
        );

    // merkle proof
    let storage_root = compute_merkle_root(
            storage_leaf_hash, hash_paths.storage_proof.hash_path,
            hash_paths.storage_proof.node_types, 
            hash_paths.storage_proof.real_hash_path_len, 
            hash_paths.storage_proof.hash_path_bools
        );
    
    // -----------get state root -------------
    // get state root from account proof using storage_root as input
    // https://github.com/scroll-tech/go-ethereum/blob/418bc6f728b66ec9eafab3f3b0ceb14078d8a050/core/types/block.go#L69
    
    // leafhash
    let account_node_key: Field = poseidon2_domain(HASH_DOMAIN_BYTE32, split_byte32_to_fields(padded_contract));
    let account_leaf_hash = hash_account_leaf(
            account_node_key, // contains hashed contract address
            account_preimage.nonce_codesize_0,
            account_preimage.balance,
            storage_root, // input from storage proof
            account_preimage.compressed_keccak_code_hash,
            account_preimage.poseidon_code_hash,
            hash_paths.account_proof.leaf_type
        );

    // merkle proof
    let state_root = compute_merkle_root(
            account_leaf_hash, hash_paths.account_proof.hash_path,
            hash_paths.account_proof.node_types, 
            hash_paths.account_proof.real_hash_path_len, 
            hash_paths.account_proof.hash_path_bools
        );

    // done
    state_root
}



pub fn get_state_root<N>(header_rlp: [u8;N]) -> [u8; 32] {
    // header_rlp[STATE_ROOT_BLOCK_HEADER_OFFSET, STATE_ROOT_BLOCK_HEADER_OFFSET+32]
    let mut state_root:[u8;32] = [0;32];
    for i in 0..32 {
        state_root[i] = header_rlp[STATE_ROOT_BLOCK_HEADER_OFFSET+i];
    }
    state_root
}

// TODO research unconstraint node_key.to_be_bits(248) (this version is not used since it more costly currently) 
// used merkle from noir std as example
// https://github.com/noir-lang/noir/blob/49e1b0c0d45565f3e87469b77f2fef0c283f6ea1/noir_stdlib/src/merkle.nr#L5
// Returns the merkle root of the tree from the provided leaf, its hashpath, domains, using a poseidon2 with the domain argument
// pub fn compute_merkle_root<N>(leaf_hash: Field, node_key: Field, hash_path: [Field; N], node_types: [Field; N], hash_path_len: u64) -> Field {
//     // TODO  node_key.to_be_bits can be done outside of the circuit. see if thats better
//     // TODO cant use hash_path_len as n since its not a constant?
// let n = hash_path.len();
//     let node_key_bits = node_key.to_be_bits(248);
//     let bits_offset = 248-hash_path_len;
//     let mut current = leaf_hash;
//     for i in 0..n {
//         if(i<hash_path_len){
//             // TODO double check this 
//             let path_bit = node_key_bits[i+bits_offset] as bool;
//             let (hash_left, hash_right) = if path_bit {
//                 (hash_path[i], current)
//             } else {
//                 (current, hash_path[i])
//             };
//             let domain = node_types[i];
//             current = poseidon2_domain(domain,[hash_left, hash_right]);
//         }
//     }
//     current
// }

// pub fn storage_proof_on_mapping_node_key<A,S>(key: [u8;32], slot: [u8; 32], value:  [u8; 32], padded_contract: [u8;32], hash_paths: Hash_paths_state_proof<A,S>, account_preimage: Account_preimage_excl_storage) -> Field {
//     // get storage_root from storage proof
//     let storage_node_key: Field = hash_node_key_from_mapping(key, slot);
//     let storage_leaf_hash = hash_storage_leaf(storage_node_key,value,hash_paths.storage_proof.leaf_type);

//     let storage_root = compute_merkle_root(storage_leaf_hash,storage_node_key, hash_paths.storage_proof.hash_path,  hash_paths.storage_proof.node_types, hash_paths.storage_proof.real_hash_path_len);
//     // get state root from account proof using storage_root as input
//     // https://github.com/scroll-tech/go-ethereum/blob/418bc6f728b66ec9eafab3f3b0ceb14078d8a050/core/types/block.go#L69
//     let account_node_key: Field = poseidon2_domain(HASH_DOMAIN_BYTE32, split_byte32_to_fields(padded_contract));
//     let account_leaf_hash = hash_account_leaf(
//         account_node_key, // contains hashed contract address
//         account_preimage.nonce_codesize_0,
//         account_preimage.balance,
//         storage_root, // input from storage proof
//         account_preimage.compressed_keccak_code_hash,
//         account_preimage.poseidon_code_hash,
//         hash_paths.account_proof.leaf_type
//         );
//     let state_root = compute_merkle_root(account_leaf_hash,account_node_key, hash_paths.account_proof.hash_path,  hash_paths.account_proof.node_types, hash_paths.account_proof.real_hash_path_len);


//     state_root
// }
