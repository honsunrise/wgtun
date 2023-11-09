use std::alloc::Layout;

pub(crate) struct StructWriter {
    start: *mut u8,
    offset: usize,
    layout: Layout,
}

impl StructWriter {
    /// Creates a struct writer that has the given initial capacity `capacity`,
    /// and whose allocation is aligned to `align`
    pub fn new(capacity: usize, align: usize) -> Self {
        let layout = Layout::from_size_align(capacity, align).unwrap();
        let start = unsafe { std::alloc::alloc(layout) };
        // Safety:
        // start is writeable for `capacity` bytes because that is the size of the allocation
        unsafe { start.write_bytes(0, capacity) };
        Self {
            start,
            offset: 0,
            layout,
        }
    }

    /// Returns a reference of the desired type, which can be used to write a T into the
    /// buffer at the internal pointer. The internal pointer will be advanced by `size_of::<T>()` so that
    /// the next call to [`write`] will return a reference to an adjacent memory location.
    ///
    /// # Safety:
    /// The caller must ensure the internal pointer is aligned suitably for writing to a T.
    /// In most C APIs (like Wireguard NT) the structs are setup in such a way that calling write
    /// repeatedly to pack data into the buffer always yields a struct that is aligned because the
    /// previous struct was aligned.
    ///
    /// # Panics
    /// 1. If writing a struct of size T would overflow the buffer.
    /// 2. If the internal pointer does not meet the alignment requirements of T.
    pub unsafe fn write<T>(&mut self) -> &mut T {
        let size = std::mem::size_of::<T>();
        if size + self.offset > self.layout.size() {
            panic!(
                "Overflow attempting to write struct of size {}. To allocation size: {}, offset: {}",
                size,
                self.layout.size(),
                self.offset
            );
        }
        // Safety:
        // ptr is within this allocation by the bounds check above
        let ptr = unsafe { self.start.add(self.offset) };
        self.offset += size;
        assert_eq!(ptr as usize % std::mem::align_of::<T>(), 0);

        // Safety:
        // 1. This pointer is valid and within the bounds of this memory allocation
        // 2. The caller ensures that they the struct is aligned
        unsafe { &mut *ptr.cast::<T>() }
    }

    pub fn ptr(&self) -> *const u8 {
        self.start
    }
}

impl Drop for StructWriter {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.start, self.layout) };
    }
}

pub(crate) struct StructReader {
    start: *mut u8,
    offset: usize,
    layout: Layout,
}

impl StructReader {
    /// Creates a struct reader that has the given initial capacity `capacity`,
    /// and whose allocation is aligned to `align`
    pub fn new(capacity: usize, align: usize) -> Self {
        let layout = Layout::from_size_align(capacity, align).unwrap();
        let start = unsafe { std::alloc::alloc(layout) };
        Self {
            start,
            offset: 0,
            layout,
        }
    }

    /// Reads a given type from the internal buffer.
    /// This advances the internal pointer by the size of the read type, such that a given instance of
    /// the given type can only be read once.
    ///
    /// # Safety
    /// The caller must ensure the internal pointer is aligned suitably for reading a T.
    /// In most C APIs (like Wireguard NT) the structs are setup in such a way that calling read
    /// repeatedly to read packed data always yields a struct that is aligned because the
    /// previous struct was aligned.
    ///
    /// # Panics
    /// 1. If reading a struct of size T would overflow the buffer.
    /// 2. If the internal pointer does not meet the alignment requirements of T.
    pub unsafe fn read<T>(&mut self) -> T {
        let size = std::mem::size_of::<T>();
        if size + self.offset > self.layout.size() {
            panic!(
                "Overflow attempting to read struct of size {}. To allocation size: {}, offset: {}",
                size,
                self.layout.size(),
                self.offset
            );
        }
        // Safety:
        // ptr is within this allocation by the bounds check above
        let ptr = unsafe { self.start.add(self.offset) };
        self.offset += size;
        assert_eq!(ptr as usize % std::mem::align_of::<T>(), 0);

        std::ptr::read(ptr as _)
    }

    pub fn ptr(&self) -> *const u8 {
        self.start
    }
}

impl Drop for StructReader {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.start, self.layout) };
    }
}
