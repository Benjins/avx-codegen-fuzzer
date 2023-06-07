// Come on
#![allow(unused_parens)]

//use std::arch::x86_64::{_rdtsc};

use std::time::Instant;

// Adapted from Xorshift-64
// Found at https://github.com/jj1bdx/xorshiftplus-c/blob/master/xorshift64star.c
// Public domain code based on the Xorshift algorithm

#[derive(Clone)]
pub struct Rand {
	state : u64
}

impl Rand{
	pub fn new(seed: u64) -> Rand {
		let mut new_seed = seed;
		for _ in 0..50 {
			new_seed = new_seed ^ (new_seed >> 12);
			new_seed = new_seed ^ (new_seed << 25);
			new_seed = new_seed ^ (new_seed >> 27);
		}
		
		Rand {
			state: new_seed
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
	
	pub fn rand_u64(&mut self) -> u64 {
		let lo = self.rand() as u64;
		let hi = (self.rand() as u64) << 32;
		return hi | lo;
	}
	
	pub fn rand_size(&mut self) -> usize {
		self.rand_u64() as usize
	}
}

// TODO: code dupe
fn get_timestamp_for_seed() -> u64 {
	Instant::now().elapsed().as_millis() as u64
}

impl Default for Rand {
	fn default() -> Self {
		let seed64 = get_timestamp_for_seed();//unsafe { _rdtsc() };
		//println!("Thread {} rand seed {}", std::thread::current().id().as_u64(), seed64);
		Rand::new( seed64 )
	}
}
