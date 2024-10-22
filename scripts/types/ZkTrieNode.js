import { ethers } from "ethers"

//@TODO technically not part of ZkTrieNode
export const BLOCK_HEADER_ORDERING = 
	[	
        {"timeAdded":{534352:0,			534351:0		},	"name": "parentHash"},      			 // 32 bytes
        {"timeAdded":{534352:0,			534351:0		},	"name": "sha3Uncles"},      			 // 32 bytes
        {"timeAdded":{534352:0,			534351:0		},	"name": "miner"},           			 // 32 bytes     
        {"timeAdded":{534352:0,			534351:0		},	"name": "stateRoot"},       			 // 32 bytes     
        {"timeAdded":{534352:0,			534351:0		},	"name": "transactionsRoot"},			 // 32 bytes    
        {"timeAdded":{534352:0,			534351:0		},	"name": "receiptsRoot"},    			 // 32 bytes     
        {"timeAdded":{534352:0,			534351:0		},	"name": "logsBloom"},       			 // 256 bytes 
        {"timeAdded":{534352:0,			534351:0		},	"name": "difficulty"},      			 // 32 bytes? = *big.Int   
        {"timeAdded":{534352:0,			534351:0		},	"name": "number"},          			 // 32 bytes? = *big.Int    
        {"timeAdded":{534352:0,			534351:0		},	"name": "gasLimit"},        			 //  8 bytes         
        {"timeAdded":{534352:0,			534351:0		},	"name": "gasUsed"},         			 //  8 bytes   
        {"timeAdded":{534352:0,			534351:0		},	"name": "timestamp"},       			 //  8 bytes                         
        {"timeAdded":{534352:0,			534351:0		},	"name": "extraData"},       			 // 97 bytes? just gues from trying 
        {"timeAdded":{534352:0,			534351:0		},	"name": "mixHash"},         			 // 32 bytes         
        {"timeAdded":{534352:0,			534351:0		},	"name": "nonce"},						 // 8 bytes   
        {"timeAdded":{534352:7096836,	534351:4740239	},	"name": "baseFeePerGas"},				 // in mainnet after a fork Bernoulli at scroll block 4740239 (https://docs.scroll.io/en/technology/overview/scroll-upgrades/#bernoulli-upgrade )
        {"timeAdded":{534352:-1,		534351:-1		},	"name": "withdrawalsRoot"}, 			 // in neither chains
        {"timeAdded":{534352:-1,		534351:-1		},	"name": "blobGasUsed"},
        {"timeAdded":{534352:-1,		534351:-1		},	"name": "excessBlobGas"},
        {"timeAdded":{534352:-1,		534351:-1		},	"name": "parentBeaconBlockRoot"}
	]

/**
 * 
 * @param {Object} obj
 * @param {number} obj.chainId
 * @param {number} obj.blockNumber
 * @returns {string[]} ordering
 */
export function getBlockHeaderOrdering({chainId,blockNumber}) {
	// chainId doesnt exist? blockNumber is then undefined. which is fine since undefined < blockNumber is always false
	const ordering = BLOCK_HEADER_ORDERING.filter((item)=>item.timeAdded[chainId] < blockNumber && item.timeAdded[chainId] !== -1) // only relevant header items
	return ordering
}

export const ACCOUNT_VALUE_HASH_PREIAMGE_ENCODING = [ 
    {name:"zeros", size:16}, {name:"codeSize", size:8}, {name:"nonce", size:8},
    {name:"balance", size:32},
    {name:"storageRoot", size:32},
    {name:"keccakCodeHash", size:32},
    {name:"poseidonCodeHash", size:32},
]
Object.freeze(ACCOUNT_VALUE_HASH_PREIAMGE_ENCODING)


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
	/**@type {ethers.BytesLike|string} */
	hash;
	/**@type {string} Object.keys(NodeTypes)*/
	typeName;
	/** @type {number} (between 0-9)*/
	type;
	/** @type {ethers.BytesLike} (between 0x00-0x09)*/
    typeHex
	/**@type {ethers.BytesLike} */
	nodeKey=undefined;
	/**@type {ethers.BytesLike} */
	preimageLenHex=undefined
	/**@type {ethers.BytesLike} */
	reversedCompressedFlagsHex=undefined;
	/**@type {ethers.BytesLike[]} */
	valuePreimage=[];
	/**@type {ethers.BytesLike} */
	keyPreimage=undefined;

	/**@type {bool[]} */
	compressedFlags=[];
	/**@type {ethers.BytesLike} */
	hashPathBools=[];

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
		this.typeHex = ethers.toBeHex(this.type)
		return this.typeName
	}
}