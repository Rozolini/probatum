#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = probatum_prover::decode_proof(data) {
        let _ = probatum_verifier::verify_detailed(&p);
    }
});
