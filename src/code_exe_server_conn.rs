

use std::net::TcpStream;
use std::io::{Read, Write};
use std::cell::RefCell;

pub struct CodeExeServClient {
	socket : Option<RefCell<TcpStream>>
}


pub struct CodeExeAndInput<'a> {
	pub code_bytes: &'a [u8],
	pub func_offset: u32,
	pub i_vals: &'a [i32],
	pub f_vals: &'a [f32],
	pub d_vals: &'a [f64],
	pub return_type : u32
}

// | overall msg length, incl. type (4 bytes) | type (1 byte) | return_type (4 bytes, be) | func offset (4 bytes, be) | code len (4 bytes, be) | code_bytes | num i_vals (4 bytes, be) | i_vals | ...

impl<'a> CodeExeServClient {

	pub fn new(connect_addr : &str) -> Self {
		//Self { socket: None }
		Self { socket: Some(RefCell::new(TcpStream::connect(connect_addr).unwrap())) }
	}

	// return type:
	//    bits 0-1 are base type (float, poly, int): 0 = signed int, 1 = unsigned int, 2 = float, 3 = poly
	//    bits 2-4 are ln2(bit size of the base type), e.g. int8 -> ln2(8) = 3
	//    bits 5-7 are ln2(simd count) + 1, or 0 for non-simd
	//    bits 8-9 are the array count minus 1 (so an array count of 1 is encoded as 0)
	pub fn send_exe_and_input(&self, exe_and_input : &CodeExeAndInput) -> std::io::Result<Vec<u8>> {
		let mut overall_msg = Vec::<u8>::new();
		
		overall_msg.push(0x66);
		
		overall_msg.extend_from_slice(&exe_and_input.return_type.to_be_bytes());
		//println!("Sending return type {}", exe_and_input.return_type);
		
		overall_msg.extend_from_slice(&exe_and_input.func_offset.to_be_bytes());
		//println!("Sending func offset {}", exe_and_input.func_offset);
		
		{
			let code_len_bytes = (exe_and_input.code_bytes.len() as u32).to_be_bytes();
			overall_msg.extend_from_slice(&code_len_bytes);
			overall_msg.extend_from_slice(exe_and_input.code_bytes);
		}
		
		//println!("Sending code len {}", exe_and_input.code_bytes.len());
		
		{
			let num_i_vals = (exe_and_input.i_vals.len() as u32).to_be_bytes();
			overall_msg.extend_from_slice(&num_i_vals);
			for i_val in exe_and_input.i_vals {
				overall_msg.extend_from_slice(&i_val.to_be_bytes());
			}
		}
		
		//println!("Sending {} iVals", exe_and_input.i_vals.len());
		
		{
			let num_f_vals = (exe_and_input.f_vals.len() as u32).to_be_bytes();
			overall_msg.extend_from_slice(&num_f_vals);
			for f_val in exe_and_input.f_vals {
				overall_msg.extend_from_slice(&f_val.to_be_bytes());
			}
		}
		
		{
			let num_d_vals = (exe_and_input.d_vals.len() as u32).to_be_bytes();
			overall_msg.extend_from_slice(&num_d_vals);
			for d_val in exe_and_input.d_vals {
				overall_msg.extend_from_slice(&d_val.to_be_bytes());
			}
		}

		let overall_msg_len = overall_msg.len() as u32;
		let overall_msg_len_bytes = overall_msg_len.to_be_bytes();
		
		let mut socket = self.socket.as_ref().unwrap().borrow_mut();
		socket.write(&overall_msg_len_bytes)?;
		socket.write(&overall_msg)?;
		
		let mut msg_len_buff = [0u8 ; 4];
		socket.read_exact(&mut msg_len_buff)?;
		
		let msg_len = u32::from_be_bytes(msg_len_buff);

		let mut msg = vec![0u8 ; msg_len as usize];
		
		socket.read_exact(&mut msg[..])?;

		return Ok(msg);
	}
}



