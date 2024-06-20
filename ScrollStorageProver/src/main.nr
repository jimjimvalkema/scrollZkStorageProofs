use dep::std;
use dep::std::convert::From;
use dep::std::hash::poseidon::bn254::perm;
use dep::std::hash::poseidon;
use std::field::bn254::decompose;
use dep::std::bigint;
use dep::std::{bigint::Bn254Fr,bigint::Bn254Fq, println};
use dep::std::field::bytes32_to_field;


// NodeTypeParent indicates the type of parent Node that has children.
global NodeTypeParent  = 0;
// NodeTypeLeaf indicates the type of a leaf Node that contains a key &
// value.
global NodeTypeLeaf = 1;
// NodeTypeEmpty indicates the type of an empty Node.
global NodeTypeEmpty  = 2;

// DBEntryTypeRoot indicates the type of a DB entry that indicates the
// current Root of a MerkleTree
global DBEntryTypeRoot  = 3;

global NodeTypeLeaf_New   = 4;
global NodeTypeEmpty_New  = 5;
// branch node for both child are terminal nodes
global NodeTypeBranch_0  = 6;
// branch node for left child is terminal node and right child is branch
global NodeTypeBranch_1  = 7;
// branch node for left child is branch node and right child is terminal
global NodeTypeBranch_2  = 8;
// branch node for both child are branch nodes
global NodeTypeBranch_3  = 9;

global HASH_DOMAIN_ELEMS_BASE:Field = 256; // TODO maybe change to u8 ??
global HASH_DOMAIN_BYTE32:Field     = 2 * HASH_DOMAIN_ELEMS_BASE;

//used hash_2 from noirs std as example
//https://github.com/noir-lang/noir/blob/8a322998ee60875f7abe4dc222f8fdc20cb0ee0a/noir_stdlib/src/hash/poseidon/bn254.nr#L24
//and from the go-ethereum scroll repo
//https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon.go#L157
pub fn hash_2WithDomain(domain: Field, input: [Field; 2]) -> Field {
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
    // valueHash is the cache of the hash of valuePreimage to avoid recalculating, only valid for leaf node
    valueHash: Field,           // *zkt.Hash
    // KeyPreimage is the original key value that derives the NodeKey, kept here only for proof
    KeyPreimage: [u8;32]          // *zkt.Byte32
}

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L203
// NodeHash computes the hash digest of the node by hashing the content in a
// specific way for each type of node.  This key is used as the hash of the
// Merkle tree for each node.
//func (n *Node) NodeHash() (*zkt.Hash, error) {
//n = node
pub fn node_hash(mut n: Node) -> Field {
	// if n.nodeHash == nil { // Cache the key to avoid repeated hash computations.
    if (n.nodeHash == 0x0) { // Cache the key to avoid repeated hash computations.
		// NOTE: We are not using the type to calculate the hash!
		//switch n.Type {
        
        //noir doesnt have switch statements yet. 
		if ([NodeTypeBranch_0,NodeTypeBranch_1, NodeTypeBranch_2, NodeTypeBranch_3].any(|branchType| branchType == n.Type)) { // H(ChildL || ChildR)
            n.nodeHash = hash_elems_with_domain(n.Type,n.ChildL, n.ChildR, &[]);
        } else if (n.Type == NodeTypeLeaf_New) {
			n.valueHash = handling_elems_and_byte32(n.CompressedFlags, n.ValuePreimage);
            n.nodeHash = leaf_hash(n.NodeKey, n.valueHash);

        } else if (n.Type == NodeTypeEmpty_New) {
            n.nodeHash = 0x0;
        }  else if ([NodeTypeEmpty, NodeTypeLeaf, NodeTypeParent].any(|branchType| branchType == n.Type)) { 
            assert(false,"encounter deprecated node types");
            //TODO cleanup
        } else {
            //n.nodeHash = &zkt.HashZero
            n.nodeHash = 0x0; //TODO make sure this is true
            // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/hash.go#L50
        }
    }
	n.nodeHash
}

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/util.go#L48
// HandlingElemsAndByte32 hash an arry mixed with field and byte32 elements, turn each byte32 into
// field elements first then calculate the hash with HashElems
// TODO elems always contains [u8; 32] but length can be variable so: [[u8; 32]]
pub fn handling_elems_and_byte32(flagArray: u32, elems: [[u8; 32]]) -> Field {
	//ret := make([]*big.Int, len(elems))
    let mut ret: [Field] = &[];
	for i in 0 .. elems.len() {
		if ((flagArray as u8) & 1<< (i as u8) != 0) {
            // elem.Hash() is just hash_2WithDomain with elem split up in 16 bytes
            // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/byte32.go#L9
            // TODO check if we can split with bn254 decompose without losing data
            let (firstHalf, lastHalf) = split_byte32_to_fields(elems[i]);
			ret = ret.push_back(hash_2WithDomain(HASH_DOMAIN_BYTE32 as Field,[firstHalf, lastHalf]));
		} else {
			// ret[i] = new(big.Int).SetBytes(elem[:])
            // not sure but it looks like its just the go version of put it in 32 bytes and pad with zeros
            // TODO research https://pkg.go.dev/math/big#Int.SetBytes
            
            //silly ah way to do elems[i][1:]
            ret = ret.push_back(be_bytes32_to_fied(elems[i]));
		}
	}
    if ret.len() < 2 {
        for i in 0 .. (2 -elems.len()) {
            ret = ret.push_back(0x0);
        }
    }

    // is this a bug?? why trip up and hash a zero when there is only 1 item??
	// if ret.len() < 2 {
    //     assert(false, "TODO implement NewHashFromBigInt");
		
    //     //NewHashFromBigInt(ret[0]), nil
	// }

    // TODO do this cleaner when noir gets array slicing maybe??
    let (retFirstEl, ret) = ret.pop_front();
    let (retSecondEl, ret) = ret.pop_front();
	hash_elems(retFirstEl, retSecondEl, ret)
}

//splits into 2 byte16 arrays with padded zero at start
pub fn split_byte32(el: [u8;32]) -> ([u8;16], [u8;16]) {
    let mut firstHalf: [u8;16] = [0;16];
    let mut lastHalf:  [u8;16] = [0;16];
    for i in 0..16 {
        firstHalf[i] = el[i];
        lastHalf[i] = el[16+i];
    }
    (firstHalf, lastHalf)
}

pub fn split_byte32_to_fields(bytes: [u8;32]) -> (Field, Field) {
    let mut firstHalf: Field = 0x0;
    let mut lastHalf: Field = 0x0;

    let mut offset = 1;
    for i in 1..17 {
        firstHalf = firstHalf.add((bytes[16-i] as Field).mul(offset));
        lastHalf = lastHalf.add((bytes[32-i] as Field).mul(offset));
        offset *= 256;
    }
    (firstHalf, lastHalf)
}

fn be_bytes16_to_fied(bytes: [u8; 16]) -> Field {
    let mut res: Field = 0;
    let mut offset = 1;
    let b_len = bytes.len();
    // TODO check if this is faster done inside the for
    let itter_len = b_len+1;
    //cant reverse itter in noir so we do a silly
    for i in 1..itter_len {
        res = res.add((bytes[b_len-i] as Field).mul(offset));
        offset *= 256;
    }
    res
}

//splits into 2 byte32 arrays with padded zero at start
pub fn split_byte32_to_bytes32(el: [u8;32]) -> ([u8;32], [u8;32]) {
    let mut firstHalf: [u8;32] = [0;32];
    let mut lastHalf:  [u8;32] = [0;32];
    for i in 16..32 {
        firstHalf[i] = el[i-16];
        lastHalf[i] = el[i];
    }
    (firstHalf, lastHalf)
}

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/util.go#L40
// HashElems call HashElemsWithDomain with a domain of HASH_DOMAIN_ELEMS_BASE(256)*<element counts>
pub fn hash_elems(firstEl: Field, secondEl: Field, elems: [Field]) -> Field {
    let domain: Field = (elems.len() as Field * HASH_DOMAIN_ELEMS_BASE + HASH_DOMAIN_BYTE32);
	hash_elems_with_domain(domain,firstEl, secondEl, elems)
}

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/util.go#L10
// HashElemsWithDomain performs a recursive poseidon hash over the array of ElemBytes, each hash
// reduce 2 fieds into one, with a specified domain field which would be used in
// every recursiving call
pub fn hash_elems_with_domain(domain: Field, firstElem: Field, secondElem: Field, elems: [Field]) -> Field {
    let l = elems.len();
	let mut baseH: Field = hash_2WithDomain(domain, [firstElem, secondElem]);
    if l == 1 {
		baseH  = hash_elems_with_domain(domain, baseH, elems[0], &[]);
	} else if l != 0 {
        assert(false, "NOT IMPLEMENTED hash_elems_with_domain l > 1");
        //TODO compiler panics from this report the bug
        // let mut tmp:[Field] = &[]; 
        // let tmpLen = (l+1)/2;
        // //tmp =: make([]*big.Int, (l+1)/2)
        // for i in 0 .. tmpLen {
        //     if (i+1)*2 > l {
        //         tmp = tmp.push_back(elems[i*2]);
        //     } else {
        //         tmp = tmp.push_back(hash_2WithDomain(domain, [elems[i*2] , elems[(i+1)*2]] ));
        //     }
        // }
        // //TODO research if can be done without popping
        // let (firstEl, poppedTmp) = tmp.pop_front();
        // baseH = hash_elems_with_domain(domain, baseH, firstEl, poppedTmp);
    
    }
    

    
    
    baseH

    
}






// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L179
// LeafHash computes the key of a leaf node given the hIndex and hValue of the
// entry of the leaf.
// func LeafHash(k, v *zkt.Hash) (*zkt.Hash, error) {
// 	return zkt.HashElemsWithDomain(big.NewInt(int64(NodeTypeLeaf_New)), k.BigInt(), v.BigInt())
// }
pub fn leaf_hash(key: Field, valueHash: Field) -> Field {
	hash_elems_with_domain(NodeTypeLeaf_New, key, valueHash, &[])
}

// NewHashFromBigInt returns a *Hash representation of the given *big.Int
// basically converts int to reverse byte order
//func NewHashFromBigInt(b *big.Int) *Hash {
// pub fn new_hash_from_big_int(b: Field) -> Field {
//     let reversed = b.to_le_bytes(32);
//     reversed.
// 	// r := &Hash{}
// 	// copy(r[:], ReverseByteOrder(b.Bytes()))
// 	// return r
// }

fn be_bytes31_to_fied(bytes: [u8; 31]) -> Field {
    let mut res: Field = 0;
    let mut offset = 1;
    let b_len = bytes.len();
    // TODO check if this is faster done inside the for
    let itter_len = b_len+1;
    //cant reverse itter in noir so we do a silly
    for i in 1..itter_len {
        res = res.add((bytes[b_len-i] as Field).mul(offset));
        offset *= 256;
    }
    res
}

// ignores first byte
fn be_bytes32_to_fied(bytes: [u8; 32]) -> Field {
    let mut res: Field = 0;
    let mut offset = 1;
    let b_len = bytes.len();
    // TODO check if this is faster done inside the for
    //cant reverse itter in noir so we do a silly

    // start at 1 to ignore first byte
    for i in 1..b_len {
        res = res.add((bytes[b_len-i] as Field).mul(offset));
        offset *= 256;
    }
    res
}


// Decomposes a single field into two 16 byte fields.
fn compute_decomposition(x_bytes: [u8; 32]) -> (Field, Field) {
    //let x_bytes = x.to_le_bytes(32);

    let mut low: Field = 0;
    let mut high: Field = 0;

    let mut offset = 1;
    for i in 0..16 {
        low += (x_bytes[i] as Field) * offset;
        high += (x_bytes[i + 16] as Field) * offset;
        offset *= 256;
    }

    (low, high)
}


#[test]
// fn test_main() {
//     let preimage12 = [1, 2];
//     let hashFixed2 = poseidon::bn254::hash_2(preimage12);
//     assert(hashFixed2 == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a);
//     //matches  HashFixed([]*big.Int{1, 2})
//     //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L41

//     //HashFixedWithDomain([]*big.Int{b1, b2}, big.NewInt(256))
//     //https://github.com/scroll-tech/go-ethereum/blob/e2becce6a1a48f5680c105b03b37a646e5740167/crypto/poseidon/poseidon_test.go#L99
//     let mut hashFixedDomain = hash_2WithDomain(256, preimage12);
//     assert(hashFixedDomain == 0x05390df727dcce2ddb8faa3acb4798ad4e95b74de05e5cc7e40496658913ae85);

//     //https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L16
//     //first byte specifies node type which is used as the domain

//     //-------------storageKey----------------
//     let storageKeyPreImageArr = [
//         0x0000000000000000000000004402c128c2337d7a6c4c867be68f7714a4e06429, 0x0000000000000000000000000000000000000000000000000000000000000000
//     ];
//     //ethers.keccak(storageKeyPreImageConcat)
//     //identifier of the storage value and contains the key and slot of the mapping 
//     let storageKey = 0xdd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff;

//     //root of storage proof, used in account proof to walk the merkle path to blockheader
//     let storageHash = 0x0d5ae1b455fb8efc1be9a7f90e3b312ecaf3ff46930a6f2e0c3ecfb04cb950cd;

//     // account leaf deconstructed
//     // leaf node        = node key , value len , compress flag , <value len> * value field, key preimage ;
//     // 0x04 //prefix leafnode
//     // 108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a // nodekey as field
//     // 01010000                                                         // value len??
//     // 00000000000000000000000000000000000000000000000000900661d8af4c86 // value
//     // 20
//     // dd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff // storageKey
//     // 0x04                                                             // node type
//     // 20e9fb498ff9c35246d527da24aa1710d2cc9b055ecf9a95a8a2a11d3d836cdf // leaf sybling?
//     // 05080000                                                         // no clue???
//     // 00000000000000000000000000000000                                 // reserved 16 bytes of zeros (32 zeros)
//     // 00000000000016ef                                                 // codesize 8 bytes
//     // 0000000000000000                                                 // nonce 8 bytes
//     // 0000000000000000000000000000000000000000000001395d857ace5efb1c6e // balance padded 32 byte
//     // 098b50a409452b9e258d144cfe5f87e70c68cab71945db8f596b6447c811de51 // storageRoot
//     // e8c4073351c26b9831c1e5af153b9be4713a4af9edfdf32b58077b735e120f14 // keccakCodeHash
//     // 136a7980da529d9e8d3a71433fc9dc5aa8c01e3a4eb60cb3a4f9cf9ca5c8e0be // poseidonCodeHash
//     // 20
//     // 5300000000000000000000000000000000000004000000000000000000000000 // contract address padded left 32 byte                                                           // means key preImg not availible


//     // key = poseidon(<pre key>, <value hash>)

//     // pre_key = poseidon(field(1), <node key>)

//     // value_hash = poseidon(<leaf element>, <leaf element>) | poseidon(<value hash>, <value hash>)

//     // leaf_element = <value field as field> | poseidon(<compressed field as field>, <compressed field as field>) | field(0)

//     //We encode the path of a new leaf node by traversing the secure key from Least Significant Bit (LSB) to the Most Significant Bit (MSB). At each step, if the bit is 0, we will traverse to the left child; otherwise, traverse to the right child.
//     // start at end, 0 = left


//     //--------------nodeKey-----------------------
//     //https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L149
//     //nodeKey := h{256}(storageKey[0:16], storageKey[16:32])
//     //no padding
//     let mut storageKeySplit = [0xdd4d389a3e50efed8ae09dd0fdc3adaf, 0x1beae58fd2204e19758755085d876cff];
//     //ethers.hexlify(ethers.toBeArray("0xdd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff").reverse()).slice(2).match(/.{1,32}/g).map((x)=>"0x"+x)
//     //storageKeySplit = [0xff6c875d08558775194e20d28fe5ea1b,0xafadc3fdd09de08aedef503e9a384ddd];
//     let mut nodeKey = hash_2WithDomain(256, storageKeySplit);
//     println("nodeKey: storageKeyPreImageArr");
//     println(nodeKey);

//     //--------------valueHash-----------------------
//     //valueHash = h{512}(storageValue[0:16], storageValue[16:32])
//     //no padding
//     let mut valueSplit = [0x00000000000000000000000000000000, 0x000000000000000000900661d8af4c86];
//     //ethers.zeroPadValue("0x900661d8af4c86",32).slice(2).match(/.{1,2}/g).reverse().join("").match(/.{1,32}/g).map((x)=>"0x"+x).toString()
//     //valueSplit = [0x864cafd8610690000000000000000000,0x00000000000000000000000000000000];
//     println("valueSplit");
//     let mut valueHash = hash_2WithDomain(0x50, valueSplit);
//     println(valueHash);

//     //----------leafNodeHash-------------
//     //leafNodeHash = h{LeafNodeType}(nodeKey, valueHash)

//     // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L19
//     // // NodeTypeLeaf indicates the type of a leaf Node that contains a key &
// 	// // value.
// 	// NodeTypeLeaf NodeType = 1
//     let leafNodeType = 0x01;
//     let mut leafNodeHash = hash_2WithDomain(leafNodeType, [nodeKey, valueHash]);
//     println("leafNodeHash");
//     println(leafNodeHash);

//     let mut nodeType = 0x04;
//     let mut leafSybling = 0x108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a;
//     let mut leafNodeWithSyblingHash = hash_2WithDomain(nodeType, [leafNodeHash, leafSybling]);
//     println("leafNodeWithSyblingHash Left");
//     println(leafNodeWithSyblingHash);
//     // leafNodeWithSyblingHash = hash_2WithDomain(nodeType, [leafSybling, leafNodeHash]);
//     // println("leafNodeWithSyblingHash Right");
//     // println(leafNodeWithSyblingHash);

    // leafNodeProofDeconstructed
    // 0x04                                                                                          1  byte
    // 108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a // node key                  32 byte            
    // 01010000                                                         // compressed flag array     4  bytes long
    // 00000000000000000000000000000000000000000000000000900661d8af4c86 // value                     32 byte   
    // 20                                                               // preImageSize = 32 bit     1  byte   
    // dd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff // storage key               32 bye

// }

fn test_storage_leaf_hash() {    
    // leaf as in proof
    // 0x04108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a0101000000000000000000000000000000000000000000000000000000900661d8af4c8620dd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff
    
    //leafNodeProofDeconstructed
    // 0x04                                                             // leafNode type             1  byte
    // 108e2f19fe8f4794f6bf4f3f21fbc2d6330e6043e97a4c660d9618c7c3958e0a // node key                  32 byte            
    // 01010000                                                         // compressed flag array     4  bytes long
    // 00000000000000000000000000000000000000000000000000900661d8af4c86 // value                     32 byte   
    // 20                                                               // preImageSize = 32 bit     1  byte   
    // dd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff // storage key               32 bye
    
    // 0x4402c128c2337d7a6c4c867be68f7714a4e06429 = address in mapping lookup on erc balance
    // value = ethers.toBeArray("0x4402c128c2337d7a6c4c867be68f7714a4e06429")
    // zeros = Array(32 - value.length).fill(0);
    // [...zeros, ...value]
    let key: [u8] = [0,0,0,0,0,0,0,0,0,0,0,0,68,2,193,40,194,51,125,122,108,76,134,123,230,143,119,20,164,224,100,41]; 

    // value = ethers.toBeArray("0x00")
    // zeros = Array(32 - value.length).fill(0);
    // [...zeros, ...value]
    let slot: [u8] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] ;
    
    let storageKeyPreImg: [u8; 64] = key.append(slot).as_array();
    let storageKeyBytes = std::hash::keccak256(storageKeyPreImg,64);
    //---------decoded-inputs----------------------------------------
    // node key preImage Hashing. NodeKeyPreImage = storageProof.key
    //0xdd4d389a3e50efed8ae09dd0fdc3adaf1beae58fd2204e19758755085d876cff
    let leafNodeType:Field = 0x04;

    // valuePreimageBytes = balance of the address in the lookup (0x4402c128c2337d7a6c4c867be68f7714a4e06429)
    let valuePreimageBytes: [[u8;32]] = [[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,144,6,97,216,175,76,134]];
    //---------------------------------------------------------------
    
    //NodeKey
    let (storageKeyFstHlf, storageKeyLstHlf) = split_byte32_to_fields(storageKeyBytes);
    let nodeKey = hash_2WithDomain(512, [storageKeyFstHlf, storageKeyLstHlf]);

    //Value Hash
    let (valuePreImgFst, valuePreImgLst) = split_byte32_to_fields(valuePreimageBytes[0]);
    let valueHash = hash_2WithDomain(512, [valuePreImgFst, valuePreImgLst]);
    
    //NodeHash
    let nodeHash = hash_2WithDomain(leafNodeType,[nodeKey, valueHash]);

    assert(nodeHash == 0x11d073e461847e567d35ce97d013e9aaf7d7915ff548fb896b0e91e9c8aefbbe,  "node_hash doesnt match");

}

