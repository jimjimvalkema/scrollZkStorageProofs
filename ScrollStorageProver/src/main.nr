use dep::std;
use dep::std::hash::poseidon::bn254::perm;
use dep::std::hash::poseidon;

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

    //https://github.com/scroll-tech/zktrie/blob/main/trie/zk_trie_node.go
    //first byte specifies node type which is used as the domain
    let nodeType = 0x09;
    let preimageLeaves= [0x232d6d20d20e4b6ee98805702e8e3e71652ea6fabd193b22a1a246dd332c0c50,0x0083262fe48f25beae26c5e2d69b6ff4b3a8ab269b684f048018dc540ec88e97];
    
    //https://docs.scroll.io/en/technology/sequencer/zktrie/#node-hashing
    let digest = hash_2WithDomain(nodeType,preimageLeaves);
    assert(digest ==  0x0d5ae1b455fb8efc1be9a7f90e3b312ecaf3ff46930a6f2e0c3ecfb04cb950cd);
}

