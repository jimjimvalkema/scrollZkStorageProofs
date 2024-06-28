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

// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L203
// NodeHash computes the hash digest of the node by hashing the content in a
// specific way for each type of node.  This key is used as the hash of the
// Merkle tree for each node.
//func (n *Node) NodeHash() (*zkt.Hash, error) {
//n = node
pub fn compute_node_hash(mut n: Node) -> Field {
	// if n.nodeHash == nil { // Cache the key to avoid repeated hash computations.
    if (n.nodeHash == 0x0) { // Cache the key to avoid repeated hash computations.
		// NOTE: We are not using the type to calculate the hash!
		//switch n.Type {
        
        //noir doesnt have switch statements yet. 
		if ([NodeTypeBranch_0,NodeTypeBranch_1, NodeTypeBranch_2, NodeTypeBranch_3].any(|branchType| branchType == n.Type)) { // H(ChildL || ChildR)
            n.nodeHash = hash_elems_with_domain(n.Type,n.ChildL, n.ChildR, &[]);
        } else if (n.Type == NodeTypeLeaf_New) {
			n.value_hash = handling_elems_and_byte32(n.CompressedFlags, n.ValuePreimage);
            n.nodeHash = leaf_hash(n.NodeKey, n.value_hash);

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
            // elem.Hash() is just hash_2_with_domain with elem split up in 16 bytes
            // https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/types/byte32.go#L9
            // TODO check if we can split with bn254 decompose without losing data
            let splitBytes:[Field;2] = split_byte32_to_fields(elems[i]);
			ret = ret.push_back(hash_2_with_domain(HASH_DOMAIN_BYTE32 as Field,splitBytes));
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
	let mut baseH: Field = hash_2_with_domain(domain, [firstElem, secondElem]);
    if l == 1 {
		baseH  = hash_elems_with_domain(domain, baseH, elems[0], &[]);
	} else if l != 0 {
        assert(false, "NOT IMPLEMENTED hash_elems_with_domain l > 1");
        // TODO compiler panics from this report the bug
        // let mut tmp:[Field] = &[]; 
        // let tmpLen = (l+1)/2;
        // //tmp =: make([]*big.Int, (l+1)/2)
        // for i in 0 .. tmpLen {
        //     if (i+1)*2 > l {
        //         tmp = tmp.push_back(elems[i*2]);
        //     } else {
        //         tmp = tmp.push_back(hash_2_with_domain(domain, [elems[i*2] , elems[(i+1)*2]] ));
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
pub fn leaf_hash(key: Field, value_hash: Field) -> Field {
	hash_elems_with_domain(NodeTypeLeaf_New, key, value_hash, &[])
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
