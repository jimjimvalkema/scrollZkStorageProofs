use dep::std;
use dep::std::hash::poseidon::bn254::perm;
use dep::std::hash::poseidon;
use dep::std::hash::poseidon2;

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
    println(hashFixed2);
    assert(hashFixed2 == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a); //matches HashFixed([]
    println("hash with domain");
    
    //HashFixedWithDomain([]*big.Int{b1, b2}, big.NewInt(256))
    let mut hashFixedDomain = hash_2WithDomain(256, preimage12);
    println(hashFixedDomain);
    assert(hashFixedDomain == 0x05390df727dcce2ddb8faa3acb4798ad4e95b74de05e5cc7e40496658913ae85);

}

