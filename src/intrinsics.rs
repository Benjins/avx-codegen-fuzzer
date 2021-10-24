#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum X86BaseType {
	Void,
	Int8,
	UInt8,
	Int16,
	UInt16,
	Int32,
	UInt32,
	Int64,
	UInt64,
	Float32,
	Float64
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum X86SIMDEType {
	Int8,
	UInt8,
	Int16,
	UInt16,
	Int32,
	UInt32,
	Int64,
	UInt64,
	Float32,
	Float64,
	M64,
	M128,
	M256,
	Mask,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum X86SIMDType {
	Primitive(X86BaseType),
	ConstantImmediate(X86BaseType, i32),
	M64(X86SIMDEType),
	M128(X86SIMDEType),
	M128d(X86SIMDEType),
	M128i(X86SIMDEType),
	M256(X86SIMDEType),
	M256d(X86SIMDEType),
	M256i(X86SIMDEType),
}

pub fn is_simd_etype_floating_point(simd_etype : X86SIMDEType) -> bool {
	match simd_etype {
		X86SIMDEType::Float32 => true,
		X86SIMDEType::Float64 => true,
		X86SIMDEType::M64 => true,
		X86SIMDEType::M128 => true,
		X86SIMDEType::M256=> true,
		_ => false
	}
}

pub fn is_simd_type_floating_point(simd_type : X86SIMDType) -> bool {
	match simd_type {
		X86SIMDType::Primitive(X86BaseType::Float32) => true,
		X86SIMDType::Primitive(X86BaseType::Float64) => true,
		X86SIMDType::Primitive(_) => false,
		X86SIMDType::ConstantImmediate(X86BaseType::Float32,_) => true,
		X86SIMDType::ConstantImmediate(X86BaseType::Float64,_) => true,
		X86SIMDType::ConstantImmediate(_,_) => false,
		X86SIMDType::M64(e_type) => is_simd_etype_floating_point(e_type),
		X86SIMDType::M128(e_type) => is_simd_etype_floating_point(e_type),
		X86SIMDType::M128d(_) => true,
		X86SIMDType::M128i(_) => false,
		X86SIMDType::M256(e_type) => is_simd_etype_floating_point(e_type),
		X86SIMDType::M256d(_) => true,
		X86SIMDType::M256i(_) => false,
	}
}

pub fn base_type_to_cpp_type_name(base_type : X86BaseType) -> &'static str {
	match base_type {
		X86BaseType::Void => "void",
		X86BaseType::Int8 => "char",
		X86BaseType::UInt8 => "unsigned char",
		X86BaseType::Int16 => "short",
		X86BaseType::UInt16 => "unsigned short",
		X86BaseType::Int32 => "int",
		X86BaseType::UInt32 => "unsigned int",
		X86BaseType::Int64 => "long long",
		X86BaseType::UInt64 => "unsigned long long",
		X86BaseType::Float32 => "float",
		X86BaseType::Float64 => "double"
	}
}

pub fn simd_type_to_cpp_type_name(simd_type : X86SIMDType) -> &'static str {
	match simd_type {
		X86SIMDType::Primitive(base_type) => base_type_to_cpp_type_name(base_type),
		X86SIMDType::ConstantImmediate(base_type, _) => base_type_to_cpp_type_name(base_type),
		X86SIMDType::M64(_) => "__m64",
		X86SIMDType::M128(_) => "__m128",
		X86SIMDType::M128d(_) => "__m128d",
		X86SIMDType::M128i(_) => "__m128i",
		X86SIMDType::M256(_) => "__m256",
		X86SIMDType::M256d(_) => "__m256d",
		X86SIMDType::M256i(_) => "__m256i"
	}
}


#[derive(Debug, Clone)]
pub struct X86SIMDIntrinsic {
	pub intrinsic_name : String,
	pub return_type : X86SIMDType,
	pub param_types : Vec<X86SIMDType>,
}

pub fn get_underlying_simd_type(node_type : X86SIMDType) -> X86SIMDType {
	if matches!(node_type, X86SIMDType::M128i(X86SIMDEType::Mask)) {
		X86SIMDType::M256i(X86SIMDEType::UInt32)
	}
	else if matches!(node_type, X86SIMDType::M256i(X86SIMDEType::Mask)) {
		X86SIMDType::M256i(X86SIMDEType::UInt32)
	}
	else {
		node_type
	}
}
