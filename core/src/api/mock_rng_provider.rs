use crate::api::rng_provider::RngProvider;
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};

pub struct MockRngProvider {
    rng: StdRng,
}

impl MockRngProvider {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
        }
    }
}

impl RngCore for MockRngProvider {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.try_fill_bytes(dest)
    }
}


impl CryptoRng for MockRngProvider {}
impl RngProvider for MockRngProvider {}
