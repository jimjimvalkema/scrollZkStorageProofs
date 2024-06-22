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
	NodeTypeBranch_3: 9.
}
Object.freeze(NodeTypes)


export class MptNode {
	//TODO make single object
    type;
    typeName;

    childR;
    childL;
    hash;
	
    constructor() {
        Object.seal(this)
    }

    setType(type) {
        const typeName = Object.keys(NodeTypes).find(key => NodeTypes[key] === type);
        if (!typeName in NodeTypes) {
            throw new Error('invalid type');
        }
        this.type = type;
        this.typeName = typeName;
    }
}