#![no_std]

/// Must be memory aligned
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BackendPorts {
    pub ports: [u16; 4],
    pub index: usize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendPorts {}

