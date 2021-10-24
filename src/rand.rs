use std::arch::x86_64::{_rdtsc};

// Adapted from Xorshift-64
// Found at https://github.com/jj1bdx/xorshiftplus-c/blob/master/xorshift64star.c
// Public domain code based on the Xorshift algorithm

#[derive(Clone)]
pub struct Rand {
	state : u64
}

impl Rand{
	pub fn new(seed: u64) -> Rand {
		Rand{
			state: seed
		}
	}

	pub fn rand(&mut self) -> u32 {
		self.state ^= (self.state >> 12);
		self.state ^= (self.state << 25);
		self.state ^= (self.state >> 27);
		return (self.state & 0xFFFFFFFF) as u32;
	}
	
	pub fn randf(&mut self) -> f32 {
		const PRECISION : u32 = 64*1024;
		let i_val = self.rand() % PRECISION;
		return i_val as f32 / PRECISION as f32;
	}
	
	pub fn rand_size(&mut self) -> usize {
		self.state ^= (self.state >> 12);
		self.state ^= (self.state << 25);
		self.state ^= (self.state >> 27);
		return self.state as usize;
	}
}

impl Default for Rand {
	fn default() -> Self {
		let seed64 = unsafe { _rdtsc() };
		Rand::new( seed64 )
	}
}
