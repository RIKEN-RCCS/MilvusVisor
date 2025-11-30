use core::cell::UnsafeCell;
use core::ptr;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

#[repr(transparent)]
pub struct VolatileCell<T> {
    inner: UnsafeCell<T>,
}

impl<T> VolatileCell<T> {
    pub fn read(&self) -> T {
        unsafe { read_volatile(self.inner.get()) }
    }

    pub fn write(&self, val: T) {
        unsafe {
            write_volatile(self.inner.get(), val);
        }
    }
}

#[repr(transparent)]
struct VolatileBuffer {
    inner: [u8; 8 * 1024 * 1024],
}

impl VolatileBuffer {
    fn copy_from_slice(&mut self, data: &[u8]) {
        assert!(data.len() <= 8 * 1024 * 1024);

        // TODO: use u64 to reduce the number of writes
        for (i, &d) in data.iter().enumerate() {
            let ptr = ptr::from_mut(&mut self.inner[i]);
            unsafe {
                write_volatile(ptr, d);
            }
        }
    }

    fn get(&self) -> &[u8] {
        &self.inner
    }
    fn get_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

#[repr(C)]
pub struct SharedMemory {
    write_done: VolatileCell<bool>,
    read_done: VolatileCell<bool>,
    len: VolatileCell<usize>,
    data: VolatileBuffer, // TODO: use a dynamic size?
}

impl SharedMemory {
    pub fn clear(&mut self) {
        self.len.write(0);
        fence(Ordering::Release);
        self.write_done.write(false);
        self.read_done.write(true);
    }

    pub fn is_ready_to_read(&self) -> bool {
        self.write_done.read()
    }

    pub fn is_ready_to_write(&self) -> bool {
        self.read_done.read()
    }

    pub fn write(&mut self, data: &[u8]) {
        while !self.read_done.read() {}
        fence(Ordering::Acquire);
        self.data.copy_from_slice(data);
        self.len.write(data.len());
        fence(Ordering::Release);
        self.read_done.write(false);
        self.write_done.write(true);
    }

    pub fn read(&self) -> Option<&[u8]> {
        if !self.write_done.read() {
            return None;
        }
        fence(Ordering::Acquire);
        let len = self.len.read();
        if len == 0 {
            None
        } else {
            Some(&self.data.get()[..len])
        }
    }

    pub fn modify(&mut self, f: impl FnOnce(&mut [u8]), len: usize) {
        while !self.read_done.read() {}
        fence(Ordering::Acquire);
        assert!(len <= self.data.get().len());
        f(&mut self.data.get_mut()[..len]);
        self.len.write(len);
        fence(Ordering::Release);
        self.read_done.write(false);
        self.write_done.write(true);
    }
}
