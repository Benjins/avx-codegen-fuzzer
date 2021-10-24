

use std::process::{Command, Stdio};
use std::io::Write as IOWrite;
use std::time::{Duration, Instant};

#[derive(Default, Debug, Clone)]
pub struct TestCompilation {
	compiler_exe : String,
	pub compiler_args : Vec<String>,
	pub code_filename : String,
	timeout_seconds : i32
}

#[derive(Default, Debug, Clone)]
pub struct TestRuntime {
	pub program_exe : String
}

enum ProcessResult {
	Success(String),
	Error(i32, String, String),
	Timeout
}

pub enum GenCodeResult {
	Success,
	CompilerTimeout,
	CompilerFailure(i32, String, String),
	RuntimeFailure(String, i32),
	RuntimeDiff(String) // input that triggered the diff
}

// Returns the output of the process if successful, or the error code if not, or that it timed out
fn run_process_with_timeout(exe : &str, args : &Vec<String>, input : &str, timeout_seconds : Option<i32>) -> ProcessResult {
	let mut child = Command::new(exe)
		.args(args)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("command failed to start");

	let mut stdin = child.stdin.take().expect("Failed to open stdin");
	stdin.write_all(input.as_bytes()).expect("Failed to write to stdin");
	
	let compile_start = Instant::now();
	loop {
		if let Some(timeout_seconds) = timeout_seconds {
			if Instant::now().duration_since(compile_start) > Duration::from_secs(timeout_seconds as u64) {
				print!("'{}' process timed out (if Windows maybe check we aren't leaking something?)\n", exe);
				child.kill().expect("Unable to kill child process");

				// Let's see if this helps...
				std::thread::sleep(Duration::from_millis(500));
				return ProcessResult::Timeout;
			}
		}
		
		match child.try_wait() {
			Ok(Some(_)) => { break; }
			Ok(None) => {
				std::thread::sleep(Duration::from_millis(100));
			}
			Err(e) => panic!("error attempting to wait: {}", e)
		}
	}

	let output = child.wait_with_output().expect("could not read output of command");
	
	if output.status.success() {
		let proc_stdout = String::from_utf8_lossy(&output.stdout);
		return ProcessResult::Success(proc_stdout.to_string());
	}
	else {
		let status_code = output.status.code().expect("failed to get exit code");
		let proc_stdout = String::from_utf8_lossy(&output.stdout);
		let proc_stderr = String::from_utf8_lossy(&output.stderr);
		return ProcessResult::Error(status_code, proc_stdout.to_string(), proc_stderr.to_string());
	}
}

pub fn test_generated_code_compilation(code : &str, compiles : &Vec<TestCompilation>) -> GenCodeResult {
	// TODO: better way?
	std::fs::write(&compiles[0].code_filename, code).expect("couldn't write to file?");
	for compile in compiles {
		let compile_result = run_process_with_timeout(&compile.compiler_exe, &compile.compiler_args, "", Some(compile.timeout_seconds));

		match compile_result {
			ProcessResult::Error(err_code, stdout, stderr) => {
				return GenCodeResult::CompilerFailure(err_code, stdout, stderr);
			}
			ProcessResult::Timeout => {
				return GenCodeResult::CompilerTimeout;
			}
			_ => { /*do nothing*/ }
		}
	}

	return GenCodeResult::Success;
}

pub fn test_generated_code_runtime(runtimes : &Vec<TestRuntime>, input : &str) -> GenCodeResult {
	// Seems reasonable I guess
	const RUNTIME_TIMEOUT : i32 = 5;
	let mut first_output = None;
	for runtime in runtimes {
		let runtime_result = run_process_with_timeout(&runtime.program_exe, &Vec::<String>::new(), input, Some(RUNTIME_TIMEOUT));
		
		match runtime_result {
			ProcessResult::Error(err_code, _stdout, _stderr) => {
				return GenCodeResult::RuntimeFailure(input.to_string(), err_code);
			}
			ProcessResult::Timeout => {
				panic!("Why did this time out??\n");
			}
			ProcessResult::Success(program_output) => {
				// If any outputs are different from the first,
				// we've failed (one of the compilers has generated bad code...or we messed up)
				if let Some(ref first_output) = first_output {
					if program_output != *first_output {
						return GenCodeResult::RuntimeDiff(input.to_string());
					}
				}
				else {
					first_output = Some(program_output);
				}
			}
		}
	}
	
	return GenCodeResult::Success;
}

#[derive(Debug, Clone)]
pub enum GenCodeFuzzMode {
	CrashOnly,
	CrashAndDiff
}

fn parse_fuzz_mode(mode_str : &str) -> GenCodeFuzzMode {
	if mode_str == "crash+diff" {
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
			code_filename : "".to_string(),
			timeout_seconds : timeout
		});
	}
	
	return (test_compilations, fuzz_mode);
}


