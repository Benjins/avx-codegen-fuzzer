

use std::process::{Command, Stdio};
use std::io::Write as IOWrite;
//use std::time::{Duration, Instant};

use crate::parse_exe::parse_obj_file;
use crate::exec_mem::ExecPage;

#[derive(Default, Debug, Clone)]
pub struct TestCompilation {
	pub compiler_exe : String,
	pub compiler_args : Vec<String>,
	pub timeout_seconds : i32
}

//#[derive(Clone)]
pub struct CompiledCodeOutput {
	pub code_page : ExecPage
}

enum ProcessResult {
	Success(Vec<u8>),
	Error(i32, String, String),
	Timeout
}

pub enum GenCodeResult {
	Success(Vec<CompiledCodeOutput>), // stdout of program
	CompilerTimeout,
	CompilerFailure(i32, String, String),
	RuntimeDiff(String)
}

// Returns the output of the process if successful, or the error code if not, or that it timed out
fn run_process_with_timeout(exe : &str, args : &Vec<String>, input : &str, _timeout_seconds : Option<i32>) -> ProcessResult {
	//print!("Running process {:?} with args {:?}\n", exe, args);
	let mut child = Command::new(exe)
		.args(args)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("command failed to start");

	//let mut stdin = child.stdin.take().expect("Failed to open stdin");
	//stdin.write_all(input.as_bytes()).expect("Failed to write to stdin");
	//drop(stdin);


	// https://doc.rust-lang.org/std/process/index.html
	// If the child process fills its stdout buffer, it may end up
	// waiting until the parent reads the stdout, and not be able to
	// read stdin in the meantime, causing a deadlock.
	// Writing from another thread ensures that stdout is being read
	// at the same time, avoiding the problem.
	{
		let mut stdin = child.stdin.take().expect("Failed to open stdin");
		let input = input.to_string();
		std::thread::spawn(move || {
			stdin.write_all(input.as_bytes()).expect("Failed to write to stdin");
		});
	}
	
	//let compile_start = Instant::now();
	//loop {
	//	if let Some(timeout_seconds) = timeout_seconds {
	//		if Instant::now().duration_since(compile_start) > Duration::from_secs(timeout_seconds as u64) {
	//			print!("'{}' process timed out (if Windows maybe check we aren't leaking something?)\n", exe);
	//			let kill_res = child.kill();
	//			
	//			if kill_res.is_err() {
	//				print!("Got error when killing process {:?}\n", kill_res);
	//			}
	//
	//			// Let's see if this helps...
	//			std::thread::sleep(Duration::from_millis(500));
	//			return ProcessResult::Timeout;
	//		}
	//	}
	//	
	//	match child.try_wait() {
	//		Ok(Some(_)) => { break; }
	//		Ok(None) => {
	//			std::thread::sleep(Duration::from_millis(100));
	//		}
	//		Err(e) => panic!("error attempting to wait: {}", e)
	//	}
	//}

	// TODO: Timeouts....gahhhh....
	let output = child.wait_with_output().expect("could not read output of command");
	
	if output.status.success() {
		let proc_stdout = output.stdout;
		return ProcessResult::Success(proc_stdout);
	}
	else {
		let status_code = output.status.code().expect("failed to get exit code");
		//let proc_stdout = String::from_utf8_lossy(&output.stdout);
		let proc_stderr = String::from_utf8_lossy(&output.stderr);
		// TODO: stdout no longer printable since it's code output
		// stderr still good tho
		return ProcessResult::Error(status_code, "".to_string(), proc_stderr.to_string());
	}
}

pub fn test_generated_code_compilation(code : &str, compiles : &Vec<TestCompilation>) -> GenCodeResult {
	// TODO: better way?
	//std::fs::write(&compiles[0].code_filename, code).expect("couldn't write to file?");
	
	let mut generated_codes = Vec::<CompiledCodeOutput>::new();
	
	for compile in compiles {
		let compile_result = run_process_with_timeout(&compile.compiler_exe, &compile.compiler_args, code, Some(compile.timeout_seconds));

		match compile_result {
			ProcessResult::Error(err_code, stdout, stderr) => {
				return GenCodeResult::CompilerFailure(err_code, stdout, stderr);
			}
			ProcessResult::Timeout => {
				return GenCodeResult::CompilerTimeout;
			}
			ProcessResult::Success(proc_output) => {
				let code_page = parse_obj_file(&proc_output, "do_stuff").unwrap();
				//println!("{:?}", code_page);
				generated_codes.push(CompiledCodeOutput { code_page: code_page });
			}
		}
	}

	return GenCodeResult::Success(generated_codes);
}

#[derive(Debug, Clone)]
pub enum GenCodeFuzzMode {
	CrashOnly,
	CrashAndDiff,
	CrashAndOptBait
}

fn parse_fuzz_mode(mode_str : &str) -> GenCodeFuzzMode {
	if mode_str == "crash+optbait" {
		return GenCodeFuzzMode::CrashAndOptBait;
	}
	else if mode_str == "crash+diff" {
		return GenCodeFuzzMode::CrashAndDiff;
	}
	else if mode_str == "crash" {
		return GenCodeFuzzMode::CrashOnly;
	}
	else {
		panic!("Could not understand testing mode '{}'", mode_str);
	}
}

// return struct at some point
pub fn parse_compiler_config(config : &str) -> (Vec<TestCompilation>, GenCodeFuzzMode) {
	let config_json : serde_json::Value = serde_json::from_str(config).expect("Could not parse JSON");
	
	let timeout = config_json["compilation_timeout_seconds"].as_i64().expect("could not parse compilation_timeout_seconds") as i32;
	
	let fuzz_mode_str = config_json["mode"].as_str().expect("could not parse mode");
	let fuzz_mode = parse_fuzz_mode(fuzz_mode_str);
	
	let mut test_compilations = Vec::<TestCompilation>::with_capacity(8);
	
	for compilation in config_json["compilations"].as_array().expect("compilations must be an array") {
		let compiler_exe = compilation["compiler_exe"].as_str().expect("Could not parse compiler_exe").to_string();
		let mut compiler_args = Vec::<String>::with_capacity(8);
		for compiler_arg in compilation["compiler_args"].as_array().expect("compiler_args must be an array") {
			compiler_args.push(compiler_arg.as_str().expect("compiler_args must contain strings").to_string());
		}
		
		test_compilations.push(TestCompilation {
			compiler_exe : compiler_exe,
			compiler_args :compiler_args,
			timeout_seconds : timeout
		});
	}
	
	return (test_compilations, fuzz_mode);
}



