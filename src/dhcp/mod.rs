pub const UDP_SERVER_PORT: u16 = 67;
pub const UDP_CLIENT_PORT: u16 = 68;

mod clientv4;
pub use self::clientv4::Client as Dhcpv4Client;
