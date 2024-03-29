
use std::fmt::Write;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ARMBaseType {
	Void,
	Int8,
	UInt8,
	Int16,
	UInt16,
	Int32,
	UInt32,
	Int64,
	UInt64,
	Float16,
	Float32,
	Float64,
	BFloat16,
	Poly8,
	Poly16,
	Poly32,
	Poly64,
	Poly128
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ARMSIMDType {
	Primitive(ARMBaseType),
	ConstantIntImmediate(i32, i32), // The valid range (min, max) and for now only integers allowed
	SIMD(ARMBaseType, i32),
	SIMDArr(ARMBaseType, i32, i32)
}


#[derive(Debug, Clone)]
pub struct ARMSIMDIntrinsic {
	pub intrinsic_name : String,
	pub return_type : ARMSIMDType,
	pub param_types : Vec<ARMSIMDType>
}

pub fn parse_arm_simd_type(type_name : &str) -> ARMSIMDType {
	match type_name {
		"void" => ARMSIMDType::Primitive(ARMBaseType::Void),

		"int8_t"  => ARMSIMDType::Primitive(ARMBaseType::Int8),
		"int16_t" => ARMSIMDType::Primitive(ARMBaseType::Int16),
		"int32_t" => ARMSIMDType::Primitive(ARMBaseType::Int32),
		"int64_t" => ARMSIMDType::Primitive(ARMBaseType::Int64),

		"uint8_t"  => ARMSIMDType::Primitive(ARMBaseType::UInt8),
		"uint16_t" => ARMSIMDType::Primitive(ARMBaseType::UInt16),
		"uint32_t" => ARMSIMDType::Primitive(ARMBaseType::UInt32),
		"uint64_t" => ARMSIMDType::Primitive(ARMBaseType::UInt64),

		"float16_t" => ARMSIMDType::Primitive(ARMBaseType::Float16),
		"float32_t" => ARMSIMDType::Primitive(ARMBaseType::Float32),
		"float64_t" => ARMSIMDType::Primitive(ARMBaseType::Float64),

		"poly8_t"  => ARMSIMDType::Primitive(ARMBaseType::Poly8),
		"poly16_t" => ARMSIMDType::Primitive(ARMBaseType::Poly16),
		"poly32_t" => ARMSIMDType::Primitive(ARMBaseType::Poly32),
		"poly64_t" => ARMSIMDType::Primitive(ARMBaseType::Poly64),
		"poly128_t" => ARMSIMDType::Primitive(ARMBaseType::Poly128),

		"int8x8_t"  => ARMSIMDType::SIMD(ARMBaseType::Int8, 8),
		"int8x16_t" => ARMSIMDType::SIMD(ARMBaseType::Int8, 16),
		"int16x4_t" => ARMSIMDType::SIMD(ARMBaseType::Int16, 4),
		"int16x8_t" => ARMSIMDType::SIMD(ARMBaseType::Int16, 8),
		"int32x2_t" => ARMSIMDType::SIMD(ARMBaseType::Int32, 2),
		"int32x4_t" => ARMSIMDType::SIMD(ARMBaseType::Int32, 4),
		"int64x1_t" => ARMSIMDType::SIMD(ARMBaseType::Int64, 1),
		"int64x2_t" => ARMSIMDType::SIMD(ARMBaseType::Int64, 2),
		
		"uint8x8_t"  => ARMSIMDType::SIMD(ARMBaseType::UInt8, 8),
		"uint8x16_t" => ARMSIMDType::SIMD(ARMBaseType::UInt8, 16),
		"uint16x4_t" => ARMSIMDType::SIMD(ARMBaseType::UInt16, 4),
		"uint16x8_t" => ARMSIMDType::SIMD(ARMBaseType::UInt16, 8),
		"uint32x2_t" => ARMSIMDType::SIMD(ARMBaseType::UInt32, 2),
		"uint32x4_t" => ARMSIMDType::SIMD(ARMBaseType::UInt32, 4),
		"uint64x1_t" => ARMSIMDType::SIMD(ARMBaseType::UInt64, 1),
		"uint64x2_t" => ARMSIMDType::SIMD(ARMBaseType::UInt64, 2),

		"float16x4_t" => ARMSIMDType::SIMD(ARMBaseType::Float16, 4),
		"float16x8_t" => ARMSIMDType::SIMD(ARMBaseType::Float16, 8),
		"float32x2_t" => ARMSIMDType::SIMD(ARMBaseType::Float32, 2),
		"float32x4_t" => ARMSIMDType::SIMD(ARMBaseType::Float32, 4),
		"float64x1_t" => ARMSIMDType::SIMD(ARMBaseType::Float64, 1),
		"float64x2_t" => ARMSIMDType::SIMD(ARMBaseType::Float64, 2),
		
		"poly8x8_t"  => ARMSIMDType::SIMD(ARMBaseType::Poly8, 8),
		"poly8x16_t" => ARMSIMDType::SIMD(ARMBaseType::Poly8, 16),
		"poly16x4_t" => ARMSIMDType::SIMD(ARMBaseType::Poly16, 4),
		"poly16x8_t" => ARMSIMDType::SIMD(ARMBaseType::Poly16, 8),
		"poly32x2_t" => ARMSIMDType::SIMD(ARMBaseType::Poly32, 2),
		"poly32x4_t" => ARMSIMDType::SIMD(ARMBaseType::Poly32, 4),
		"poly64x1_t" => ARMSIMDType::SIMD(ARMBaseType::Poly64, 1),
		"poly64x2_t" => ARMSIMDType::SIMD(ARMBaseType::Poly64, 2),

		"int8x8x2_t"  => ARMSIMDType::SIMDArr(ARMBaseType::Int8,  8, 2),
		"int8x16x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int8, 16, 2),
		"uint8x8x2_t"  => ARMSIMDType::SIMDArr(ARMBaseType::UInt8,  8, 2),
		"uint8x16x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt8, 16, 2),

		"int8x8x3_t"  => ARMSIMDType::SIMDArr(ARMBaseType::Int8,  8, 3),
		"int8x16x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int8, 16, 3),
		"uint8x8x3_t"  => ARMSIMDType::SIMDArr(ARMBaseType::UInt8,  8, 3),
		"uint8x16x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt8, 16, 3),

		"int8x8x4_t"  => ARMSIMDType::SIMDArr(ARMBaseType::Int8,  8, 4),
		"int8x16x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int8, 16, 4),
		"uint8x8x4_t"  => ARMSIMDType::SIMDArr(ARMBaseType::UInt8,  8, 4),
		"uint8x16x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt8, 16, 4),

		"int16x4x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int16, 4, 2),
		"int16x8x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int16, 8, 2),
		"uint16x4x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt16, 4, 2),
		"uint16x8x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt16, 8, 2),

		"int16x4x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int16, 4, 3),
		"int16x8x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int16, 8, 3),
		"uint16x4x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt16, 4, 3),
		"uint16x8x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt16, 8, 3),

		"int16x4x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int16, 4, 4),
		"int16x8x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int16, 8, 4),
		"uint16x4x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt16, 4, 4),
		"uint16x8x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt16, 8, 4),

		"int32x2x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int32, 2, 2),
		"int32x4x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int32, 4, 2),
		"uint32x2x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt32, 2, 2),
		"uint32x4x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt32, 4, 2),
		
		"int32x2x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int32, 2, 3),
		"int32x4x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int32, 4, 3),
		"uint32x2x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt32, 2, 3),
		"uint32x4x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt32, 4, 3),

		"int32x2x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int32, 2, 4),
		"int32x4x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int32, 4, 4),
		"uint32x2x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt32, 2, 4),
		"uint32x4x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt32, 4, 4),

		"int64x1x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int64, 1, 2),
		"int64x2x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int64, 2, 2),
		"uint64x1x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt64, 1, 2),
		"uint64x2x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt64, 2, 2),

		"int64x1x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int64, 1, 3),
		"int64x2x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int64, 2, 3),
		"uint64x1x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt64, 1, 3),
		"uint64x2x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt64, 2, 3),

		"int64x1x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int64, 1, 4),
		"int64x2x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Int64, 2, 4),
		"uint64x1x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt64, 1, 4),
		"uint64x2x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::UInt64, 2, 4),

		"float16x4x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float16, 4, 2),
		"float16x8x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float16, 8, 2),
		"float32x2x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float32, 2, 2),
		"float32x4x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float32, 4, 2),
		"float64x1x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float64, 1, 2),
		"float64x2x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float64, 2, 2),

		"float16x4x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float16, 4, 3),
		"float16x8x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float16, 8, 3),
		"float32x2x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float32, 2, 3),
		"float32x4x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float32, 4, 3),
		"float64x1x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float64, 1, 3),
		"float64x2x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float64, 2, 3),

		"float16x4x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float16, 4, 4),
		"float16x8x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float16, 8, 4),
		"float32x2x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float32, 2, 4),
		"float32x4x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float32, 4, 4),
		"float64x1x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float64, 1, 4),
		"float64x2x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Float64, 2, 4),

		"poly8x8x2_t"  => ARMSIMDType::SIMDArr(ARMBaseType::Poly8, 8, 2),
		"poly8x16x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly8, 16, 2),
		"poly16x4x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly16, 4, 2),
		"poly16x8x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly16, 8, 2),
		"poly32x2x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly32, 2, 2),
		"poly32x4x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly32, 4, 2),
		"poly64x1x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly64, 1, 2),
		"poly64x2x2_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly64, 2, 2),

		"poly8x8x3_t"  => ARMSIMDType::SIMDArr(ARMBaseType::Poly8, 8, 3),
		"poly8x16x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly8, 16, 3),
		"poly16x4x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly16, 4, 3),
		"poly16x8x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly16, 8, 3),
		"poly32x2x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly32, 2, 3),
		"poly32x4x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly32, 4, 3),
		"poly64x1x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly64, 1, 3),
		"poly64x2x3_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly64, 2, 3),

		"poly8x8x4_t"  => ARMSIMDType::SIMDArr(ARMBaseType::Poly8, 8, 4),
		"poly8x16x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly8, 16, 4),
		"poly16x4x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly16, 4, 4),
		"poly16x8x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly16, 8, 4),
		"poly32x2x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly32, 2, 4),
		"poly32x4x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly32, 4, 4),
		"poly64x1x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly64, 1, 4),
		"poly64x2x4_t" => ARMSIMDType::SIMDArr(ARMBaseType::Poly64, 2, 4),

		"bfloat16_t" => ARMSIMDType::Primitive(ARMBaseType::BFloat16),
		"bfloat16x4_t" => ARMSIMDType::SIMD(ARMBaseType::BFloat16, 4),
		"bfloat16x8_t" => ARMSIMDType::SIMD(ARMBaseType::BFloat16, 8),

		other_name => panic!("Bad {}", other_name)
	}
}

pub fn is_arm_base_type_floating_point(base_type : ARMBaseType) -> bool {
	match base_type {
		ARMBaseType::BFloat16 | ARMBaseType::Float16 | ARMBaseType::Float32 | ARMBaseType::Float64 => true,
		_ => false
	}
}

pub fn is_arm_simd_type_floating_point(simd_type : ARMSIMDType) -> bool {
	match simd_type {
		ARMSIMDType::Primitive(base_type) => is_arm_base_type_floating_point(base_type),
		ARMSIMDType::ConstantIntImmediate(_, _) => false,
		ARMSIMDType::SIMD(base_type, _) => is_arm_base_type_floating_point(base_type),
		ARMSIMDType::SIMDArr(base_type, _, _) => is_arm_base_type_floating_point(base_type)
	}
}

pub fn arm_base_type_size_bytes(base_type : ARMBaseType) -> usize {
	match base_type {
		ARMBaseType::Void => panic!("cannot take size of void"),
		ARMBaseType::Int8 | ARMBaseType::UInt8 => 1,
		ARMBaseType::Int16 | ARMBaseType::UInt16 => 2,
		ARMBaseType::Int32 | ARMBaseType::UInt32 => 4,
		ARMBaseType::Int64 | ARMBaseType::UInt64 => 8,
		ARMBaseType::Float16 => 2,
		ARMBaseType::Float32 => 4,
		ARMBaseType::Float64 => 8,
		ARMBaseType::BFloat16 => 2,
		ARMBaseType::Poly8 => 1,
		ARMBaseType::Poly16 => 2,
		ARMBaseType::Poly32 => 4,
		ARMBaseType::Poly64 => 8,
		ARMBaseType::Poly128 => 16
	}
}

pub fn arm_simd_type_size_bytes(simd_type : ARMSIMDType) -> usize {
	match simd_type {
		ARMSIMDType::Primitive(base_type) => arm_base_type_size_bytes(base_type),
		ARMSIMDType::ConstantIntImmediate(_, _) => panic!("Cannot call size on constant immediate"),
		ARMSIMDType::SIMD(base_type, count) => arm_base_type_size_bytes(base_type) * count as usize,
		ARMSIMDType::SIMDArr(base_type, count, arr_len) => arm_base_type_size_bytes(base_type) * (count * arr_len) as usize
	}
}

pub fn is_arm_simd_type_base_type(simd_type : ARMSIMDType, in_base_type : ARMBaseType) -> bool {
	match simd_type {
		ARMSIMDType::Primitive(base_type) => base_type == in_base_type,
		ARMSIMDType::ConstantIntImmediate(_, _) => false,
		ARMSIMDType::SIMD(base_type, _) => base_type == in_base_type,
		ARMSIMDType::SIMDArr(base_type, _, _) => base_type == in_base_type
	}
}

pub fn is_arm_simd_type_simd(simd_type : ARMSIMDType) -> bool {
	match simd_type {
		ARMSIMDType::Primitive(_) => false,
		ARMSIMDType::ConstantIntImmediate(_, _) => false,
		ARMSIMDType::SIMD(_, _) => true,
		ARMSIMDType::SIMDArr(_, _, _) => true
	}
}


pub fn arm_base_type_to_cpp_type_name(base_type : ARMBaseType) -> &'static str {
	match base_type {
		ARMBaseType::Void => "void",
		ARMBaseType::Int8 => "int8_t",
		ARMBaseType::UInt8 => "uint8_t",
		ARMBaseType::Int16 => "int16_t",
		ARMBaseType::UInt16 => "uint16_t",
		ARMBaseType::Int32 => "int32_t",
		ARMBaseType::UInt32 => "uint32_t",
		ARMBaseType::Int64 => "int64_t",
		ARMBaseType::UInt64 => "uint64_t",
		ARMBaseType::Float16 => "float16_t",
		ARMBaseType::Float32 => "float32_t",
		ARMBaseType::Float64 => "float64_t",
		ARMBaseType::BFloat16 => "bfloat16_t",
		ARMBaseType::Poly8 => "poly8_t",
		ARMBaseType::Poly16 => "poly16_t",
		ARMBaseType::Poly32 => "poly32_t",
		ARMBaseType::Poly64 => "poly64_t",
		ARMBaseType::Poly128 => "poly128_t"
	}
}

fn arm_make_simd_type_name(base_type_name : &str, count : i32) -> String {
	let mut type_name = base_type_name.to_string();
	
	// Remote the '_t' at the end
	for _ in 0..2 { type_name.pop(); }
	write!(&mut type_name, "x{}_t", count).expect("");
	return type_name;
}

fn arm_make_simd_arr_type_name(base_type_name : &str, count : i32, array_len : i32) -> String {
	let mut type_name = base_type_name.to_string();
	
	// Remote the '_t' at the end
	for _ in 0..2 { type_name.pop(); }
	write!(&mut type_name, "x{}x{}_t", count, array_len).expect(""	);
	return type_name;
}

pub fn arm_simd_type_to_cpp_type_name(simd_type : ARMSIMDType) -> String {
	match simd_type {
		ARMSIMDType::Primitive(base_type) => arm_base_type_to_cpp_type_name(base_type).to_string(),
		ARMSIMDType::ConstantIntImmediate(_, _) => arm_base_type_to_cpp_type_name(ARMBaseType::Int32).to_string(),
		ARMSIMDType::SIMD(base_type, count) => arm_make_simd_type_name(arm_base_type_to_cpp_type_name(base_type), count),
		ARMSIMDType::SIMDArr(base_type, count, array_len) => arm_make_simd_arr_type_name(arm_base_type_to_cpp_type_name(base_type), count, array_len)
	}
}

fn arm_base_type_to_load_abbrev(base_type : ARMBaseType) -> &'static str {
	match base_type {
		ARMBaseType::Void => panic!("cannot call load abbrev on void"),
		ARMBaseType::Int8 => "s8",
		ARMBaseType::UInt8 => "u8",
		ARMBaseType::Int16 => "s16",
		ARMBaseType::UInt16 => "u16",
		ARMBaseType::Int32 => "s32",
		ARMBaseType::UInt32 => "u32",
		ARMBaseType::Int64 => "s64",
		ARMBaseType::UInt64 => "u64",
		ARMBaseType::Float16 => "f16",
		ARMBaseType::Float32 => "f32",
		ARMBaseType::Float64 => "f64",
		ARMBaseType::BFloat16 => "bf16",
		ARMBaseType::Poly8 => "p8",
		ARMBaseType::Poly16 => "p16",
		ARMBaseType::Poly32 => "p32",
		ARMBaseType::Poly64 => "p64",
		ARMBaseType::Poly128 => "p128"
	}
}

pub fn arm_simd_type_to_ld_func(simd_type : ARMSIMDType) -> String {
	let size = arm_simd_type_size_bytes(simd_type);
	
	match simd_type {
		ARMSIMDType::Primitive(_) => { panic!("Cannot get load func for primitive"); }
		ARMSIMDType::ConstantIntImmediate(_, _) => { panic!("Cannot get load func for constant immediate"); }
		ARMSIMDType::SIMD(base_type, _) => {
			if size == 8 {
				let mut ld_func = "vld1_".to_string();
				ld_func.push_str(arm_base_type_to_load_abbrev(base_type));
				return ld_func;
			}
			else if size == 16 {
				let mut ld_func = "vld1q_".to_string();
				ld_func.push_str(arm_base_type_to_load_abbrev(base_type));
				return ld_func;
			}
			else {
				panic!("Bad size {} on simd type {:?}", size, simd_type);
			}
		}
		ARMSIMDType::SIMDArr(base_type, _, array_len) => {
			let array_len = array_len as usize;
			let elem_size = size / array_len;
			if elem_size == 8 {
				let mut ld_func = "vld1_".to_string();
				ld_func.push_str(arm_base_type_to_load_abbrev(base_type));
				write!(ld_func, "_x{}", array_len).expect("");
				return ld_func;
			}
			else if elem_size == 16 {
				let mut ld_func = "vld1q_".to_string();
				ld_func.push_str(arm_base_type_to_load_abbrev(base_type));
				write!(ld_func, "_x{}", array_len).expect("");
				return ld_func;
			}
			else {
				panic!("Bad size {}/{} on simd array type {:?}", size, elem_size, simd_type);
			}
		}
	}
}



