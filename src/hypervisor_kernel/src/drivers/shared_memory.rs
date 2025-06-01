use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[repr(C)]
pub struct SharedMemory {
    lock: AtomicU32,
    ready: AtomicU32,
    len: usize,
    data: [u8; 8 * 1024 * 1024], // TODO: use a dynamic size?
}

impl SharedMemory {
    fn lock(&self) {
        while self
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            != Ok(0)
        {}
    }

    fn unlock(&self) {
        self.lock.store(0, Ordering::Release);
    }

    pub fn clear(&mut self) {
        self.lock();
        self.ready.store(0, Ordering::Release);
        self.len = 0;
        self.unlock();
    }

    pub fn is_ready(&self) -> bool {
        self.lock();
        let result = self.ready.load(Ordering::Acquire) == 1;
        self.unlock();
        result
    }

    pub fn write(&mut self, data: &[u8]) {
        self.lock();
        self.data[..data.len()].copy_from_slice(data);
        self.len = data.len();
        self.ready.store(1, Ordering::Release);
        self.unlock();
    }

    pub fn read(&self) -> Option<&[u8]> {
        self.lock();
        let result: Option<&[u8]> = if self.ready.load(Ordering::Acquire) == 1 {
            let len = self.len;
            if len > 0 {
                Some(&self.data[..len])
            } else {
                None
            }
        } else {
            None
        };
        self.unlock();
        result
    }

    pub fn modify(&mut self, f: impl FnOnce(&mut [u8]), len: usize) {
        self.lock();
        f(&mut self.data[0..len]);
        self.len = len;
        self.ready.store(1, Ordering::Release);
        self.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_memory_write_read() {
        let mut shared_mem = SharedMemory {
            lock: AtomicU32::new(0),
            ready: AtomicU32::new(0),
            len: 0,
            data: [0; 1024 * 1024],
        };

        // Test writing and reading data
        let test_data = b"Hello, MilvusVisor!";
        shared_mem.write(test_data);

        // Verify data was written correctly
        assert!(shared_mem.is_ready());

        if let Some(read_data) = shared_mem.read() {
            assert_eq!(read_data, test_data);
        } else {
            panic!("Failed to read data from shared memory");
        }

        // Test clearing the shared memory
        shared_mem.clear();
        assert!(!shared_mem.is_ready());
    }
}
