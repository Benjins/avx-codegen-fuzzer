// :/
#![allow(unused_parens)]

// Opt bait is kinda just commented out for now, but left some dead code in cause lazy
#![allow(dead_code)]

// Uh, yeah nightly only I think but c'mon this is good stuff
#![feature(portable_simd)]
#![feature(thread_id_value)]
#![feature(associated_type_defaults)]

use std::collections::HashMap;
//use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use std::arch::x86_64::{_rdtsc};

use sha2::{Sha256, Digest};

mod rand;

mod compilation_config;
use compilation_config::{test_generated_code_compilation, parse_compiler_config};
use compilation_config::{TestCompilation, GenCodeResult, GenCodeFuzzMode};

mod x86_parse_spec;
use x86_parse_spec::parse_intel_intrinsics_xml;

// Kinda just need everything here
mod x86_intrinsics;
use x86_intrinsics::*;

mod parse_exe;
//use parse_exe::{ExecPage, parse_obj_file};

mod x86_codegen_ctx;
use x86_codegen_ctx::{X86SIMDCodegenCtx};

mod exec_mem;

mod codegen_fuzzing;
use codegen_fuzzing::CodegenFuzzer;

mod x86_codegen_fuzzing;
use x86_codegen_fuzzing::{X86CodegenFuzzer, X86CodegenFuzzerThreadInput, X86CodegenFuzzerCodeMetadata, X86CodeFuzzerInputValues, X86SIMDOutputValues };

fn get_hex_hash_of_bytes(input : &[u8]) -> String {
	let mut hasher = Sha256::new();
	hasher.update(input);
	let digest = hasher.finalize();
	hex::encode(digest)
}

fn save_out_failure_info(orig_code : &str, min_code : &str, result : &GenCodeResult) {
	match result {
		GenCodeResult::CompilerTimeout => {
			let min_hex_hash_full = get_hex_hash_of_bytes(min_code.as_bytes());
			let min_hex_hash = &min_hex_hash_full[0..10];
			let orig_code_filename = format!("fuzz_issues/compiler_timeouts/{}_orig.cpp", min_hex_hash);
			let min_code_filename = format!("fuzz_issues/compiler_timeouts/{}_min.cpp", min_hex_hash);
			
			std::fs::write(orig_code_filename, orig_code).expect("couldn't write to file?");
			std::fs::write(min_code_filename, min_code).expect("couldn't write to file?");
		}
		GenCodeResult::CompilerFailure(_,_,_) => {
			let min_hex_hash_full = get_hex_hash_of_bytes(min_code.as_bytes());
			let min_hex_hash = &min_hex_hash_full[0..10];
			let orig_code_filename = format!("fuzz_issues/compiler_fails/{}_orig.cpp", min_hex_hash);
			let min_code_filename = format!("fuzz_issues/compiler_fails/{}_min.cpp", min_hex_hash);
			
			std::fs::write(orig_code_filename, orig_code).expect("couldn't write to file?");
			std::fs::write(min_code_filename, min_code).expect("couldn't write to file?");
		}
		GenCodeResult::RuntimeDiff(input) => {
			let min_hex_hash_full = get_hex_hash_of_bytes(min_code.as_bytes());
			let min_hex_hash = &min_hex_hash_full[0..10];
			let orig_code_filename = format!("fuzz_issues/runtime_diffs/{}_orig.cpp", min_hex_hash);
			let min_code_filename = format!("fuzz_issues/runtime_diffs/{}_min.cpp", min_hex_hash);
			let input_filename = format!("fuzz_issues/runtime_diffs/{}_input.input", min_hex_hash);
			
			std::fs::write(orig_code_filename, orig_code).expect("couldn't write to file?");
			std::fs::write(min_code_filename, min_code).expect("couldn't write to file?");
			std::fs::write(input_filename, input).expect("couldn't write to file?");
		}
		_ => panic!("uuhhhh....implement this")
	}
}

fn fuzz_gen_simd_codegen_loop<FuzzType,ThreadInput,CodegenCtx,CodeMeta,FuzzerInput,FuzzerOutput>(
		input : ThreadInput, compilation_tests : &Vec<TestCompilation>, fuzz_mode : GenCodeFuzzMode, total_num_cases_done : Arc<AtomicUsize>, total_bugs_found : Arc<AtomicUsize>
	)
	where FuzzType : CodegenFuzzer<ThreadInput,CodegenCtx,CodeMeta,FuzzerInput,FuzzerOutput>, FuzzerOutput: Copy, CodegenCtx: Clone {
	
	let mut fuzzer = FuzzType::new_fuzzer_state(input);
	
	loop {
		let codegen_ctx = fuzzer.generate_ctx();
		
		let (cpp_code, code_meta) = fuzzer.generate_cpp_code(&codegen_ctx);
		let res = test_generated_code_compilation(&cpp_code, compilation_tests);

		match res {
			GenCodeResult::CompilerTimeout => {
				todo!();
			}
			GenCodeResult::CompilerFailure(_err_code,_,_) => {
				let minim_checker = |this_fuzzer : &FuzzType, ctx: &CodegenCtx| {
					let (minim_cpp_code, _) = this_fuzzer.generate_cpp_code(ctx);
					let minim_res = test_generated_code_compilation(&minim_cpp_code, compilation_tests);
					return matches!(minim_res, GenCodeResult::CompilerFailure(_,_,_));
				};
				
				if let Some(min_ctx) = fuzzer.try_minimize(codegen_ctx, minim_checker) {
					let (min_cpp_code,_) = fuzzer.generate_cpp_code(&min_ctx);
					save_out_failure_info(&cpp_code, &min_cpp_code, &res);
				}
				else {
					println!("Could not minimize for whatever reason");
					save_out_failure_info(&cpp_code, &cpp_code, &res);
				}
				
				total_bugs_found.fetch_add(1, Ordering::SeqCst);
			}
			GenCodeResult::Success(ref compiled_outputs) => {
				if matches!(fuzz_mode, GenCodeFuzzMode::CrashAndDiff) {
					const NUM_INPUTS_PER_CODEGEN : i32 = 1000;
					let mut bad_input : Option<FuzzerInput> = None;
					for _ in 0..NUM_INPUTS_PER_CODEGEN {
						let input = fuzzer.generate_random_input(&code_meta);

						let mut all_outputs_same = true;
						let mut first_output : Option<FuzzerOutput> = None;
						for compiled_out in compiled_outputs.iter(){
							let output = fuzzer.execute(&compiled_out.code_page, &code_meta, &input);
							if let Some(first_output) = first_output {
								if !fuzzer.are_outputs_the_same(&first_output, &output) {
									all_outputs_same = false;
									break;
								}
							}
							else {
								first_output = Some(output);
							}
						}
						
						if !all_outputs_same {
							bad_input = Some(input);
							break;
						}
					}
					
					if let Some(bad_input) = bad_input {
						let minim_checker = |this_fuzzer : &FuzzType, ctx: &CodegenCtx| {
							let (minim_cpp_code, minim_code_meta) = this_fuzzer.generate_cpp_code(ctx);
							let minim_res = test_generated_code_compilation(&minim_cpp_code, compilation_tests);
							if let GenCodeResult::Success(minim_compiled_outputs) = minim_res {

								// TODO: Code dup with above
								let mut all_outputs_same = true;
								let mut first_output : Option<FuzzerOutput> = None;
								for compiled_out in minim_compiled_outputs.iter(){
									let output = fuzzer.execute(&compiled_out.code_page, &minim_code_meta, &bad_input);
									if let Some(first_output) = first_output {
										if !fuzzer.are_outputs_the_same(&first_output, &output) {
											all_outputs_same = false;
											break;
										}
									}
									else {
										first_output = Some(output);
									}
								}
								
								return !all_outputs_same;
							}
							
							return false;
						};
						
						let input_str = fuzzer.save_input_to_string(&bad_input);
						if let Some(min_ctx) = fuzzer.try_minimize(codegen_ctx, minim_checker) {
							let (min_cpp_code,_) = fuzzer.generate_cpp_code(&min_ctx);
							save_out_failure_info(&cpp_code, &min_cpp_code, &GenCodeResult::RuntimeDiff(input_str));
						}
						else {
							println!("Could not minimize for whatever reason");
							save_out_failure_info(&cpp_code, &cpp_code, &GenCodeResult::RuntimeDiff(input_str));
						}
						
						total_bugs_found.fetch_add(1, Ordering::SeqCst);
					}
				}
			}
			_ => { panic!("bad possible return type from compilation") }
		};

		total_num_cases_done.fetch_add(1, Ordering::SeqCst);
	}
}

fn fuzz_gen_x86_simd_codegen(config_filename : &str, num_threads : u32) {
		// Open the data xml file for the intrinsics
	let intrinsics_docs_filename = "data-3.6.0.xml";
	let contents = std::fs::read_to_string(intrinsics_docs_filename);
	
	if contents.is_err() {
		print!("Could not open intrinsics docs file '{}'. Maybe you need to download it?\n", intrinsics_docs_filename);
		return;
	}
	let contents = contents.unwrap();
	
	let config_contents = std::fs::read_to_string(config_filename);
	if config_contents.is_err() {
		print!("Could not open config file '{}'\n", config_filename);
		return;
	}
	let config_contents = config_contents.unwrap();
	
	let intrinsics_list = parse_intel_intrinsics_xml(&contents);

	let type_to_intrinsics_map = {
		let mut type_to_intrinsics_map = HashMap::<X86SIMDType, Vec<X86SIMDIntrinsic>>::new();
		
		for intrinsic in intrinsics_list {
			let intrinsics_for_type = type_to_intrinsics_map.entry(intrinsic.return_type)
				.or_insert_with(|| Vec::<X86SIMDIntrinsic>::with_capacity(4));
				
			intrinsics_for_type.push(intrinsic);
		}

		type_to_intrinsics_map
	};
	
	let (compilation_tests, fuzz_mode) = parse_compiler_config(&config_contents);

	let mut thread_handles = Vec::<std::thread::JoinHandle<_>>::new();
	print!("Launching fuzzer with {} threads\n", num_threads);

	let num_cases_state = Arc::new(AtomicUsize::new(0));
	let num_bugs_found = Arc::new(AtomicUsize::new(0));
	
	// This should ensure subsequent runs don't re-use the same seeds for everything
	let initial_time = unsafe { _rdtsc() };
	
	for thread_id in 0..num_threads {
		let compilation_tests = compilation_tests.clone();

		let own_type_to_intrinsics_map = type_to_intrinsics_map.clone();
		let fuzz_mode = fuzz_mode.clone();
		let num_cases_state = num_cases_state.clone();
		let num_bugs_found = num_bugs_found.clone();
		
		// Some prime numbers beause they're better, or so I hear
		let initial_seed = ((thread_id as u64) + 937) * 241 + initial_time;
		
		let thread_input = X86CodegenFuzzerThreadInput {
			thread_seed : initial_seed,
			type_to_intrinsics_map : own_type_to_intrinsics_map
		};
		
		let thread_handle = std::thread::spawn(move || {
			fuzz_gen_simd_codegen_loop::<X86CodegenFuzzer, X86CodegenFuzzerThreadInput, X86SIMDCodegenCtx, X86CodegenFuzzerCodeMetadata, X86CodeFuzzerInputValues, X86SIMDOutputValues>(
				thread_input, &compilation_tests, fuzz_mode, num_cases_state, num_bugs_found);
		});
		thread_handles.push(thread_handle);
	}
	
	print!("Done launching\n");
	
	let start_time = Instant::now();
	loop {
		std::thread::sleep(Duration::from_secs(1));
		let time_so_far = Instant::now().duration_since(start_time);
		let seconds_so_far = time_so_far.as_secs_f32();
		let num_cases_so_far = num_cases_state.load(Ordering::SeqCst);
		let avg_cases_per_second = num_cases_so_far as f32 / seconds_so_far;
		let num_bugs_so_far = num_bugs_found.load(Ordering::SeqCst);

		print!("{:10.1} sec uptime | {:10} cases | {:10.2} cps | {:5} bugs \n",
			seconds_so_far, num_cases_so_far, avg_cases_per_second, num_bugs_so_far);
	}
}

fn print_usage() {
	print!("usage: [exe] fuzz [config_filename]\n");
}

fn get_num_threads() -> u32 {
	for (ii,arg) in std::env::args().enumerate() {
		if arg == "--threads" {
			if ii == std::env::args().len() - 1 {
				panic!("--threads was the last argument");
			}
			else {
				let thread_count_arg = std::env::args().nth(ii + 1).expect("");
				let maybe_thread_count = thread_count_arg.parse::<u32>();
				if let Ok(thread_count) = maybe_thread_count {
					return thread_count;
				}
				else {
					panic!("--threads was not followed by a number");
				}
			}
		}
	}

	// Yeah, a good default. It's definitely not me being too lazy to add 'num_cpus = "1.13.1"' to my Cargo.toml file,
	// I'd much rather write out this comment explaining my poor decisions ha ha ha
	return 4;
}

fn main() {

	//test_thing();
	//return;

	if std::env::args().count() < 2 {
		print_usage();
		return;
	}
	
	let method = std::env::args().nth(1).expect("no args?");
	if method == "fuzz" {
		let config_filename = std::env::args().nth(2).expect("missing config?");
		let num_threads = get_num_threads();
		//fuzz_simd_codegen(&config_filename, num_threads);
		fuzz_gen_x86_simd_codegen(&config_filename, num_threads);
	}
	else {
		print_usage();
		return;
	}

	// TODO: How to handle int divide-by-zero, and possibly other traps?
}
