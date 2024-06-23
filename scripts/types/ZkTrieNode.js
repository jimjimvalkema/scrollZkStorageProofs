import { ethers } from "ethers"

// NodeType defines the type of node in the MT.
// https://github.com/scroll-tech/zktrie/blob/23181f209e94137f74337b150179aeb80c72e7c8/trie/zk_trie_node.go#L16
export const NodeTypes = {
	// NodeTypeParent indicates the type of parent Node that has children.
	NodeTypeParent: 0,
	// NodeTypeLeaf indicates the type of a leaf Node that contains a key &
	// value.
	NodeTypeLeaf: 1,
	// NodeTypeEmpty indicates the type of an empty Node.
	NodeTypeEmpty: 2,

	// DBEntryTypeRoot indicates the type of a DB entry that indicates the
	// current Root of a MerkleTree
	DBEntryTypeRoot: 3,

	NodeTypeLeaf_New : 4,
	NodeTypeEmpty_New: 5,
	// branch node for both child are terminal nodes
	NodeTypeBranch_0: 6,
	// branch node for left child is terminal node and right child is branch
	NodeTypeBranch_1: 7,
	// branch node for left child is branch node and right child is terminal
	NodeTypeBranch_2: 8,
	// branch node for both child are branch nodes
	NodeTypeBranch_3: 9,
}
Object.freeze(NodeTypes)

export const leafTypes = [NodeTypes.NodeTypeLeaf_New, NodeTypes.NodeTypeEmpty_New]
Object.freeze(leafTypes)

export class ZkTrieNode {
	/**@type {number} */
    type;
	/**@type {string} */
    typeName;
	/**@type {ethers.BytesLike|string} */
	hash;

	/**@type {ethers.BytesLike} */
	mark=undefined;
	/**@type {ethers.BytesLike[]} */
	valuePreimage=[];
	/**@type {ethers.BytesLike} */
	keyPreimage=undefined;
	/**@type {ethers.BytesLike} */
	nodeKey=undefined;
	/**@type {bool[]} */
	hashPathBools=[];
	/**@type {bool[]} */
	compressedFlags=[];

	/**@type {ethers.BytesLike} */
	childR=undefined;
	/**@type {ethers.BytesLike} */
	childL=undefined;
	
    constructor({hash, type}={}) {
		this.hash = hash
		this.setType(type)
    }

	/**
	 * 
	 * @param {number} type between 0-9
	 */
	setType(type) {
		//TODO make a leaf and branch type instead
		if (type === undefined) {
			delete this.childR
			delete this.childL

			delete this.mark
			delete this.valuePreimage
			delete this.keyPreimage
			delete this.nodeKey
			delete this.hashPathBools
			delete this.compressedFlags
		} else {
			this.type = type
			this.getTypeName()
			if (leafTypes.includes(this.type)) {
				delete this.childR
				delete this.childL
			} else {
				delete this.mark
				delete this.valuePreimage
				delete this.keyPreimage
				delete this.nodeKey
				delete this.hashPathBools
				delete this.compressedFlags
			}
			Object.seal(this)
		}
	}

	/**
	 * gets current node type and finds its name
	 * also set this.typeName
	 * @returns this.typeName
	 */
	getTypeName() {
		this.typeName = Object.keys(NodeTypes).find((typeName)=>NodeTypes[typeName] === this.type)
		return this.typeName
	}
}