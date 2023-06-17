
use std::alloc::{alloc, dealloc, Layout};


pub struct AlignedSlice<T : Clone + Default, const N : usize> {
	// TODO: std::ptr::NonNull ?
	ptr : *mut T,
	len : usize
}

impl<T : Clone + Default, const N : usize> AlignedSlice<T, N> {

	pub fn new(len : usize, init_value : &T) -> Self {
		
		// TODO: Compile time check would be nice
		assert!(N >= core::mem::align_of::<T>());
		assert!(N % core::mem::align_of::<T>() == 0);
		
		let num_bytes = core::mem::size_of::<T>() * len;
		let layout = Layout::from_size_align(num_bytes, N).expect("improper layout for alligned slice");
		
		// SAFETY: We are explicitly initializing this later in this function body
		let ptr = unsafe { alloc(layout) as *mut T	 };
		
		// TODO: Propogate result?
		assert!(!ptr.is_null());
		
		let mut ret = Self {
			ptr: ptr,
			len: len
		};
		
		for element in ret.as_slice_mut().iter_mut() {
			*element = init_value.clone();
		}
		
		ret
	}

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        unsafe {
            core::slice::from_raw_parts(self.ptr, self.len)
        }
    }
    #[inline]
    pub fn as_slice_mut(&mut self) -> &mut [T] {
        unsafe {
            core::slice::from_raw_parts_mut(self.ptr, self.len)
        }
    }
}

impl<T : Clone + Default, const N : usize> Drop for AlignedSlice<T, N> {
	fn drop(&mut self) {
		
		// TODO: Some way of verifying this is the same layout as allocated, w/o storing it?
		let num_bytes = core::mem::size_of::<T>() * self.len;
		let layout = Layout::from_size_align(num_bytes, N).expect("improper layout for alligned slice");
		
		unsafe { dealloc(self.ptr as *mut u8, layout); }
	}
}

impl<T : Clone + Default, const N : usize> Clone for AlignedSlice<T, N> {
	fn clone(&self) -> Self {
		let init_val = T::default();
		let mut new_aligned_slice = Self::new(self.len, &init_val);
		
		new_aligned_slice.as_slice_mut().clone_from_slice(self.as_slice());
		
		new_aligned_slice
	}
}

impl<T : Clone + Default + core::fmt::Debug, const N : usize> core::fmt::Debug for AlignedSlice<T, N> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		write!(f, "AlignedSlice {{ {:?} }}", self.as_slice())
	}
}


#[cfg(test)]
fn test_aligned_slice_with_alignment<const N : usize>() {
	let init_value = 0i32;
	let mut aligned_slice = AlignedSlice::<i32, N>::new(7, &init_value);

	{
		let slice = aligned_slice.as_slice_mut();
		for ii in 0..7 {
			slice[ii] = ii as i32;
		}
	}

	{
		let slice = aligned_slice.as_slice();
		for ii in 0..7 {
			assert_eq!(slice[ii], ii as i32);
		}
	}
}

#[test]
#[should_panic]
fn test_aligned_slice_fail_01() {
	test_aligned_slice_with_alignment::<2>();
}

#[test]
#[should_panic]
fn test_aligned_slice_fail_02() {
	test_aligned_slice_with_alignment::<6>();
}

#[test]
fn test_aligned_slice_01() {
	test_aligned_slice_with_alignment::<4>();
}

#[test]
fn test_aligned_slice_02() {
	test_aligned_slice_with_alignment::<8>();
}

#[test]
fn test_aligned_slice_03() {
	test_aligned_slice_with_alignment::<16>();
}

#[test]
fn test_aligned_slice_04() {
	test_aligned_slice_with_alignment::<32>();
}

