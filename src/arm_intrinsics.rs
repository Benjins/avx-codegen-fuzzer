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
	Float32,
	Float64
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ARMSIMDType {
	Primitive(ARMBaseType),
	ConstantImmediate(ARMBaseType, i32),
	
}

