// See https://tools.ietf.org/html/rfc2131 for the DHCP specification.

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};

use crate::wire::arp::Hardware;
use crate::wire::{EthernetAddress, Ipv4Address};
use crate::{Error, Result};
use core::convert::TryFrom;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;
pub const MAX_DNS_SERVER_COUNT: usize = 3;

const DHCP_MAGIC_NUMBER: u32 = 0x63825363;

enum_with_unknown! {
    /// The possible opcodes of a DHCP packet.
    pub enum OpCode(u8) {
        Request = 1,
        Reply = 2,
    }
}

/// The possible system architecture types
#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub enum ClientArchType {
    X86Bios = 0,
    PC98 = 1,
    EfiItanium = 2,
    DecAlpha = 3,
    ArcX86 = 4,
    IntelLeanClient = 5,
    X86Uefi = 6,
    X64Uefi = 7,
    EfiXscale = 8,
    Ebc = 9,
    Arm32Uefi = 10,
    Arm64Uefi = 11,
    PowerPcOpenFimware = 12,
    PowerPcepapr = 13,
    PowerOpalv3 = 14,
    X86UefiHttp = 15,
    X64UefiHttp = 16,
    EbcFromHttp = 17,
    Arm32UefiHttp = 18,
    Arm64UefiHttp = 19,
    X86BiosHttp = 20,
    Arm32Uboot = 21,
    Arm64Uboot = 22,
    Arm32UbootHttp = 23,
    Arm64UbootHttp = 24,
    Riscv32Uefi = 25,
    Riscv32UefiHttp = 26,
    Riscv64Uefi = 27,
    Riscv64UefiHttp = 28,
    Riscv128Uefi = 29,
    Riscv128UefiHttp = 30,
    S390Basic = 31,
    S390Extended = 32,
    Mips32Uefi = 33,
    Mips64Uefi = 34,
    Sunway32Uefi = 35,
    Sunway64Uefi = 36,
    LoongArch32Uefi = 37,
    LoongArch32UefiHttp = 38,
    LoongArch64Uefi = 39,
    LoongArch64UefiHttp = 40,
}

impl TryFrom<u16> for ClientArchType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        use ClientArchType::*;
        let res = match value {
            0 => X86Bios,
            1 => PC98,
            2 => EfiItanium,
            3 => DecAlpha,
            4 => ArcX86,
            5 => IntelLeanClient,
            6 => X86Uefi,
            7 => X64Uefi,
            8 => EfiXscale,
            9 => Ebc,
            10 => Arm32Uefi,
            11 => Arm64Uefi,
            12 => PowerPcOpenFimware,
            13 => PowerPcepapr,
            14 => PowerOpalv3,
            15 => X86UefiHttp,
            16 => X64UefiHttp,
            17 => EbcFromHttp,
            18 => Arm32UefiHttp,
            19 => Arm64UefiHttp,
            20 => X86BiosHttp,
            21 => Arm32Uboot,
            22 => Arm64Uboot,
            23 => Arm32UbootHttp,
            24 => Arm64UbootHttp,
            25 => Riscv32Uefi,
            26 => Riscv32UefiHttp,
            27 => Riscv64Uefi,
            28 => Riscv64UefiHttp,
            29 => Riscv128Uefi,
            30 => Riscv128UefiHttp,
            31 => S390Basic,
            32 => S390Extended,
            33 => Mips32Uefi,
            34 => Mips64Uefi,
            35 => Sunway32Uefi,
            36 => Sunway64Uefi,
            37 => LoongArch32Uefi,
            38 => LoongArch32UefiHttp,
            39 => LoongArch64Uefi,
            40 => LoongArch64UefiHttp,
            _ => return Err(Error::Unrecognized),
        };
        Ok(res)
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkInterfaceType {
    /// Universal Network Device Interface
    Undi = 1,
}

impl TryFrom<u8> for NetworkInterfaceType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(NetworkInterfaceType::Undi),
            _ => Err(Error::Unrecognized),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkInterfaceVersion {
    pub interface_type: NetworkInterfaceType,
    pub major: u8,
    pub minor: u8,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MachineIdType {
    /// Globally Unique Identifier type
    Guid = 0,
}

impl TryFrom<u8> for MachineIdType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(MachineIdType::Guid),
            _ => Err(Error::Unrecognized),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MachineId<'a> {
    pub id_type: MachineIdType,
    pub id: &'a [u8],
}

enum_with_unknown! {
    /// The possible message types of a DHCP packet.
    pub enum MessageType(u8) {
        Discover = 1,
        Offer = 2,
        Request = 3,
        Decline = 4,
        Ack = 5,
        Nak = 6,
        Release = 7,
        Inform = 8,
    }
}

bitflags! {
    pub struct Flags: u16 {
        const BROADCAST = 0b1000_0000_0000_0000;
    }
}

impl MessageType {
    fn opcode(&self) -> OpCode {
        match *self {
            MessageType::Discover
            | MessageType::Inform
            | MessageType::Request
            | MessageType::Decline
            | MessageType::Release => OpCode::Request,
            MessageType::Offer | MessageType::Ack | MessageType::Nak => OpCode::Reply,
            MessageType::Unknown(_) => OpCode::Unknown(0),
        }
    }
}

/// A representation of a single DHCP option.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DhcpOption<'a> {
    EndOfList,
    Pad,
    MessageType(MessageType),
    RequestedIp(Ipv4Address),
    ClientIdentifier(EthernetAddress),
    ServerIdentifier(Ipv4Address),
    IpLeaseTime(u32),
    Router(Ipv4Address),
    SubnetMask(Ipv4Address),
    MaximumDhcpMessageSize(u16),
    TimeOffset(u32),
    ClientArchTypeList(&'a [u8]),
    ClientNetworkInterfaceId(NetworkInterfaceVersion),
    ClientMachineId(MachineId<'a>),
    VendorClassId(&'a str),
    Other { kind: u8, data: &'a [u8] },
}

impl<'a> DhcpOption<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], DhcpOption<'a>)> {
        // See https://tools.ietf.org/html/rfc2132 for all possible DHCP options.

        let (skip_len, option);
        match *buffer.get(0).ok_or(Error::Truncated)? {
            field::OPT_END => {
                skip_len = 1;
                option = DhcpOption::EndOfList;
            }
            field::OPT_PAD => {
                skip_len = 1;
                option = DhcpOption::Pad;
            }
            kind => {
                let length = *buffer.get(1).ok_or(Error::Truncated)? as usize;
                skip_len = length + 2;
                let data = buffer.get(2..skip_len).ok_or(Error::Truncated)?;

                match (kind, length) {
                    (field::OPT_END, _) | (field::OPT_PAD, _) => unreachable!(),
                    (field::OPT_DHCP_MESSAGE_TYPE, 1) => {
                        option = DhcpOption::MessageType(MessageType::from(data[0]));
                    }
                    (field::OPT_REQUESTED_IP, 4) => {
                        option = DhcpOption::RequestedIp(Ipv4Address::from_bytes(data));
                    }
                    (field::OPT_TIME_OFFSET, 4) => {
                        option = DhcpOption::TimeOffset(u32::from_be_bytes([
                            data[0], data[1], data[2], data[3],
                        ]));
                    }
                    (field::OPT_CLIENT_ARCH, _) => option = DhcpOption::ClientArchTypeList(data),
                    (field::OPT_CLIENT_MACHINE_ID, _) => {
                        if data.len() < 2 {
                            return Err(Error::Truncated);
                        }

                        let id_type = MachineIdType::try_from(data[0])?;

                        option = DhcpOption::ClientMachineId(MachineId {
                            id_type: id_type,
                            id: &data[1..],
                        });
                    }
                    (field::OPT_VENDOR_CLASS_ID, _) => {
                        let temp = core::str::from_utf8(data).map_err(|_| Error::Malformed)?;
                        option = DhcpOption::VendorClassId(temp);
                    }
                    (field::OPT_CLIENT_INTERFACE_ID, 3) => {
                        option = DhcpOption::ClientNetworkInterfaceId(NetworkInterfaceVersion {
                            interface_type: TryFrom::try_from(data[0])?,
                            major: data[1],
                            minor: data[2],
                        })
                    }
                    (field::OPT_CLIENT_ID, 7) => {
                        let hardware_type = Hardware::from(u16::from(data[0]));
                        if hardware_type != Hardware::Ethernet {
                            return Err(Error::Unrecognized);
                        }
                        option =
                            DhcpOption::ClientIdentifier(EthernetAddress::from_bytes(&data[1..]));
                    }
                    (field::OPT_SERVER_IDENTIFIER, 4) => {
                        option = DhcpOption::ServerIdentifier(Ipv4Address::from_bytes(data));
                    }
                    (field::OPT_ROUTER, 4) => {
                        option = DhcpOption::Router(Ipv4Address::from_bytes(data));
                    }
                    (field::OPT_SUBNET_MASK, 4) => {
                        option = DhcpOption::SubnetMask(Ipv4Address::from_bytes(data));
                    }
                    (field::OPT_MAX_DHCP_MESSAGE_SIZE, 2) => {
                        option = DhcpOption::MaximumDhcpMessageSize(u16::from_be_bytes([
                            data[0], data[1],
                        ]));
                    }
                    (field::OPT_IP_LEASE_TIME, 4) => {
                        option = DhcpOption::IpLeaseTime(u32::from_be_bytes([
                            data[0], data[1], data[2], data[3],
                        ]))
                    }
                    (_, _) => {
                        option = DhcpOption::Other {
                            kind: kind,
                            data: data,
                        };
                    }
                }
            }
        }
        Ok((&buffer[skip_len..], option))
    }

    pub fn buffer_len(&self) -> usize {
        match self {
            &DhcpOption::EndOfList => 1,
            &DhcpOption::Pad => 1,
            &DhcpOption::TimeOffset(_) => 6,
            &DhcpOption::MessageType(_) => 3,
            &DhcpOption::ClientIdentifier(eth_addr) => 3 + eth_addr.as_bytes().len(),
            &DhcpOption::RequestedIp(ip)
            | &DhcpOption::ServerIdentifier(ip)
            | &DhcpOption::Router(ip)
            | &DhcpOption::SubnetMask(ip) => 2 + ip.as_bytes().len(),
            &DhcpOption::MaximumDhcpMessageSize(_) => 4,
            &DhcpOption::IpLeaseTime(_) => 6,
            &DhcpOption::ClientArchTypeList(list) => 2 + list.len(),
            &DhcpOption::ClientMachineId(list) => 3 + list.id.len(),
            &DhcpOption::ClientNetworkInterfaceId(_) => 5,
            &DhcpOption::VendorClassId(list) => 2 + list.len(),
            &DhcpOption::Other { data, .. } => 2 + data.len(),
        }
    }

    pub fn emit<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        let skip_length;
        assert!(!buffer.is_empty());

        match *self {
            DhcpOption::EndOfList => {
                skip_length = 1;
                buffer[0] = field::OPT_END;
            }
            DhcpOption::Pad => {
                skip_length = 1;
                buffer[0] = field::OPT_PAD;
            }
            _ => {
                skip_length = self.buffer_len();

                assert!(skip_length <= buffer.len());
                if skip_length > buffer.len() {
                    return buffer;
                }

                buffer[1] = (skip_length - 2) as u8;
                match *self {
                    DhcpOption::EndOfList | DhcpOption::Pad => unreachable!(),
                    DhcpOption::MessageType(value) => {
                        buffer[0] = field::OPT_DHCP_MESSAGE_TYPE;
                        buffer[2] = value.into();
                    }
                    DhcpOption::VendorClassId(list) => {
                        buffer[0] = field::OPT_VENDOR_CLASS_ID;
                        buffer[2..skip_length].copy_from_slice(list.as_bytes());
                    }
                    DhcpOption::ClientArchTypeList(list) => {
                        buffer[0] = field::OPT_CLIENT_ARCH;
                        buffer[2..skip_length].copy_from_slice(list);
                    }
                    DhcpOption::ClientMachineId(list) => {
                        buffer[0] = field::OPT_CLIENT_MACHINE_ID;
                        buffer[2] = list.id_type as u8;
                        buffer[3..skip_length].copy_from_slice(list.id);
                    }
                    DhcpOption::TimeOffset(value) => {
                        buffer[0] = field::OPT_TIME_OFFSET;
                        buffer[2..6].copy_from_slice(&value.to_be_bytes()[..]);
                    }
                    DhcpOption::ClientNetworkInterfaceId(id) => {
                        buffer[0] = field::OPT_CLIENT_INTERFACE_ID;
                        buffer[2] = id.interface_type as u8;
                        buffer[3] = id.major;
                        buffer[4] = id.minor;
                    }
                    DhcpOption::ClientIdentifier(eth_addr) => {
                        buffer[0] = field::OPT_CLIENT_ID;
                        buffer[2] = u16::from(Hardware::Ethernet) as u8;
                        buffer[3..9].copy_from_slice(eth_addr.as_bytes());
                    }
                    DhcpOption::RequestedIp(ip) => {
                        buffer[0] = field::OPT_REQUESTED_IP;
                        buffer[2..6].copy_from_slice(ip.as_bytes());
                    }
                    DhcpOption::ServerIdentifier(ip) => {
                        buffer[0] = field::OPT_SERVER_IDENTIFIER;
                        buffer[2..6].copy_from_slice(ip.as_bytes());
                    }
                    DhcpOption::Router(ip) => {
                        buffer[0] = field::OPT_ROUTER;
                        buffer[2..6].copy_from_slice(ip.as_bytes());
                    }
                    DhcpOption::SubnetMask(mask) => {
                        buffer[0] = field::OPT_SUBNET_MASK;
                        buffer[2..6].copy_from_slice(mask.as_bytes());
                    }
                    DhcpOption::MaximumDhcpMessageSize(size) => {
                        buffer[0] = field::OPT_MAX_DHCP_MESSAGE_SIZE;
                        buffer[2..4].copy_from_slice(&size.to_be_bytes()[..]);
                    }
                    DhcpOption::IpLeaseTime(lease_time) => {
                        buffer[0] = field::OPT_IP_LEASE_TIME;
                        buffer[2..6].copy_from_slice(&lease_time.to_be_bytes()[..]);
                    }
                    DhcpOption::Other {
                        kind,
                        data: provided,
                    } => {
                        buffer[0] = kind;
                        buffer[2..skip_length].copy_from_slice(provided);
                    }
                }
            }
        }
        &mut buffer[skip_length..]
    }
}

/// A read/write wrapper around a Dynamic Host Configuration Protocol packet buffer.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

pub(crate) mod field {
    #![allow(non_snake_case)]
    #![allow(unused)]

    use crate::wire::field::*;

    pub const OP: usize = 0;
    pub const HTYPE: usize = 1;
    pub const HLEN: usize = 2;
    pub const HOPS: usize = 3;
    pub const XID: Field = 4..8;
    pub const SECS: Field = 8..10;
    pub const FLAGS: Field = 10..12;
    pub const CIADDR: Field = 12..16;
    pub const YIADDR: Field = 16..20;
    pub const SIADDR: Field = 20..24;
    pub const GIADDR: Field = 24..28;
    pub const CHADDR: Field = 28..44;
    pub const SNAME: Field = 44..108;
    pub const FILE: Field = 108..236;
    pub const MAGIC_NUMBER: Field = 236..240;
    pub const OPTIONS: Rest = 240..;

    // Vendor Extensions
    pub const OPT_END: u8 = 255;
    pub const OPT_PAD: u8 = 0;
    pub const OPT_SUBNET_MASK: u8 = 1;
    pub const OPT_TIME_OFFSET: u8 = 2;
    pub const OPT_ROUTER: u8 = 3;
    pub const OPT_TIME_SERVER: u8 = 4;
    pub const OPT_NAME_SERVER: u8 = 5;
    pub const OPT_DOMAIN_NAME_SERVER: u8 = 6;
    pub const OPT_LOG_SERVER: u8 = 7;
    pub const OPT_COOKIE_SERVER: u8 = 8;
    pub const OPT_LPR_SERVER: u8 = 9;
    pub const OPT_IMPRESS_SERVER: u8 = 10;
    pub const OPT_RESOURCE_LOCATION_SERVER: u8 = 11;
    pub const OPT_HOST_NAME: u8 = 12;
    pub const OPT_BOOT_FILE_SIZE: u8 = 13;
    pub const OPT_MERIT_DUMP: u8 = 14;
    pub const OPT_DOMAIN_NAME: u8 = 15;
    pub const OPT_SWAP_SERVER: u8 = 16;
    pub const OPT_ROOT_PATH: u8 = 17;
    pub const OPT_EXTENSIONS_PATH: u8 = 18;

    // IP Layer Parameters per Host
    pub const OPT_IP_FORWARDING: u8 = 19;
    pub const OPT_NON_LOCAL_SOURCE_ROUTING: u8 = 20;
    pub const OPT_POLICY_FILTER: u8 = 21;
    pub const OPT_MAX_DATAGRAM_REASSEMBLY_SIZE: u8 = 22;
    pub const OPT_DEFAULT_TTL: u8 = 23;
    pub const OPT_PATH_MTU_AGING_TIMEOUT: u8 = 24;
    pub const OPT_PATH_MTU_PLATEU_TABLE: u8 = 25;

    // IP Layer Parameters per Interface
    pub const OPT_INTERFACE_MTU: u8 = 26;
    pub const OPT_ALL_SUBNETS_ARE_LOCAL: u8 = 27;
    pub const OPT_BROADCAST_ADDRESS: u8 = 28;
    pub const OPT_PERFORM_MASK_DISCOVERY: u8 = 29;
    pub const OPT_MASK_SUPPLIER: u8 = 30;
    pub const OPT_PERFORM_ROUTER_DISCOVERY: u8 = 31;
    pub const OPT_ROUTER_SOLICITATION_ADDRESS: u8 = 32;
    pub const OPT_STATIC_ROUTE: u8 = 33;

    // Link Layer Parameters per Interface
    pub const OPT_TRAILER_ENCAPSULATION: u8 = 34;
    pub const OPT_ARP_CACHE_TIMEOUT: u8 = 35;
    pub const OPT_ETHERNET_ENCAPSULATION: u8 = 36;

    // TCP Parameters
    pub const OPT_TCP_DEFAULT_TTL: u8 = 37;
    pub const OPT_TCP_KEEPALIVE_INTERVAL: u8 = 38;
    pub const OPT_TCP_KEEPALIVE_GARBAGE: u8 = 39;

    // Application and Service Parameters
    pub const OPT_NIS_DOMAIN: u8 = 40;
    pub const OPT_NIS_SERVERS: u8 = 41;
    pub const OPT_NTP_SERVERS: u8 = 42;
    pub const OPT_VENDOR_SPECIFIC_INFO: u8 = 43;
    pub const OPT_NETBIOS_NAME_SERVER: u8 = 44;
    pub const OPT_NETBIOS_DISTRIBUTION_SERVER: u8 = 45;
    pub const OPT_NETBIOS_NODE_TYPE: u8 = 46;
    pub const OPT_NETBIOS_SCOPE: u8 = 47;
    pub const OPT_X_WINDOW_FONT_SERVER: u8 = 48;
    pub const OPT_X_WINDOW_DISPLAY_MANAGER: u8 = 49;
    pub const OPT_NIS_PLUS_DOMAIN: u8 = 64;
    pub const OPT_NIS_PLUS_SERVERS: u8 = 65;
    pub const OPT_MOBILE_IP_HOME_AGENT: u8 = 68;
    pub const OPT_SMTP_SERVER: u8 = 69;
    pub const OPT_POP3_SERVER: u8 = 70;
    pub const OPT_NNTP_SERVER: u8 = 71;
    pub const OPT_WWW_SERVER: u8 = 72;
    pub const OPT_FINGER_SERVER: u8 = 73;
    pub const OPT_IRC_SERVER: u8 = 74;
    pub const OPT_STREETTALK_SERVER: u8 = 75;
    pub const OPT_STDA_SERVER: u8 = 76;

    // DHCP Extensions
    pub const OPT_REQUESTED_IP: u8 = 50;
    pub const OPT_IP_LEASE_TIME: u8 = 51;
    pub const OPT_OPTION_OVERLOAD: u8 = 52;
    pub const OPT_TFTP_SERVER_NAME: u8 = 66;
    pub const OPT_BOOTFILE_NAME: u8 = 67;
    pub const OPT_DHCP_MESSAGE_TYPE: u8 = 53;
    pub const OPT_SERVER_IDENTIFIER: u8 = 54;
    pub const OPT_PARAMETER_REQUEST_LIST: u8 = 55;
    pub const OPT_MESSAGE: u8 = 56;
    pub const OPT_MAX_DHCP_MESSAGE_SIZE: u8 = 57;
    pub const OPT_RENEWAL_TIME_VALUE: u8 = 58;
    pub const OPT_REBINDING_TIME_VALUE: u8 = 59;
    pub const OPT_VENDOR_CLASS_ID: u8 = 60;
    pub const OPT_CLIENT_ID: u8 = 61;

    // PXE DHCP extensions
    pub const OPT_CLIENT_ARCH: u8 = 93;
    pub const OPT_CLIENT_INTERFACE_ID: u8 = 94;
    pub const OPT_CLIENT_MACHINE_ID: u8 = 97;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with DHCP packet structure.
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error::Truncated)` if the buffer is too short.
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::MAGIC_NUMBER.end {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Returns the operation code of this packet.
    pub fn opcode(&self) -> OpCode {
        let data = self.buffer.as_ref();
        OpCode::from(data[field::OP])
    }

    /// Returns the hardware protocol type (e.g. ethernet).
    pub fn hardware_type(&self) -> Hardware {
        let data = self.buffer.as_ref();
        Hardware::from(u16::from(data[field::HTYPE]))
    }

    /// Returns the length of a hardware address in bytes (e.g. 6 for ethernet).
    pub fn hardware_len(&self) -> u8 {
        self.buffer.as_ref()[field::HLEN]
    }

    /// Returns the transaction ID.
    ///
    /// The transaction ID (called `xid` in the specification) is a random number used to
    /// associate messages and responses between client and server. The number is chosen by
    /// the client.
    pub fn transaction_id(&self) -> u32 {
        let field = &self.buffer.as_ref()[field::XID];
        NetworkEndian::read_u32(field)
    }

    /// Returns the hardware address of the client (called `chaddr` in the specification).
    ///
    /// Only ethernet is supported by `smoltcp`, so this functions returns
    /// an `EthernetAddress`.
    pub fn client_hardware_address(&self) -> EthernetAddress {
        let field = &self.buffer.as_ref()[field::CHADDR][..core::mem::size_of::<EthernetAddress>()];
        EthernetAddress::from_bytes(field)
    }

    /// Returns the value of the `hops` field.
    ///
    /// The `hops` field is set to zero by clients and optionally used by relay agents.
    pub fn hops(&self) -> u8 {
        self.buffer.as_ref()[field::HOPS]
    }

    /// Returns the value of the `secs` field.
    ///
    /// The secs field is filled by clients and describes the number of seconds elapsed
    /// since client began process.
    pub fn secs(&self) -> u16 {
        let field = &self.buffer.as_ref()[field::SECS];
        NetworkEndian::read_u16(field)
    }

    /// Returns the value of the `magic cookie` field in the DHCP options.
    ///
    /// This field should be always be `0x63825363`.
    pub fn magic_number(&self) -> u32 {
        let field = &self.buffer.as_ref()[field::MAGIC_NUMBER];
        NetworkEndian::read_u32(field)
    }

    /// Returns the Ipv4 address of the client, zero if not set.
    ///
    /// This corresponds to the `ciaddr` field in the DHCP specification. According to it,
    /// this field is “only filled in if client is in `BOUND`, `RENEW` or `REBINDING` state
    /// and can respond to ARP requests”.
    pub fn client_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::CIADDR];
        Ipv4Address::from_bytes(field)
    }

    /// Returns the value of the `yiaddr` field, zero if not set.
    pub fn your_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::YIADDR];
        Ipv4Address::from_bytes(field)
    }

    /// Returns the value of the `siaddr` field, zero if not set.
    pub fn server_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::SIADDR];
        Ipv4Address::from_bytes(field)
    }

    /// Returns the value of the `giaddr` field, zero if not set.
    pub fn relay_agent_ip(&self) -> Ipv4Address {
        let field = &self.buffer.as_ref()[field::GIADDR];
        Ipv4Address::from_bytes(field)
    }

    pub fn flags(&self) -> Flags {
        let field = &self.buffer.as_ref()[field::FLAGS];
        Flags::from_bits_truncate(NetworkEndian::read_u16(field))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options(&self) -> Result<&'a [u8]> {
        let data = self.buffer.as_ref();
        data.get(field::OPTIONS).ok_or(Error::Malformed)
    }

    pub fn get_sname(&self) -> Result<&'a str> {
        let data = self.buffer.as_ref();
        let data = data.get(field::SNAME).ok_or(Error::Malformed)?;
        let len = data.iter().position(|&x| x == 0).ok_or(Error::Malformed)?;
        if len == 0 {
            return Err(Error::Finished);
        }

        let data = core::str::from_utf8(&data[..len]).map_err(|_| Error::Malformed)?;
        Ok(data)
    }

    pub fn get_boot_file(&self) -> Result<&'a str> {
        let data = self.buffer.as_ref();
        let data = data.get(field::FILE).ok_or(Error::Malformed)?;
        let len = data.iter().position(|&x| x == 0).ok_or(Error::Malformed)?;
        if len == 0 {
            return Err(Error::Finished);
        }
        let data = core::str::from_utf8(&data[..len]).map_err(|_| Error::Malformed)?;
        Ok(data)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Sets the optional `sname` (“server name”) and `file` (“boot file name”) fields to zero.
    ///
    /// The fields are not commonly used, so we set their value always to zero. **This method
    /// must be called when creating a packet, otherwise the emitted values for these fields
    /// are undefined!**
    pub fn set_sname_and_boot_file_to_zero(&mut self) {
        let data = self.buffer.as_mut();
        for byte in &mut data[field::SNAME] {
            *byte = 0;
        }
        for byte in &mut data[field::FILE] {
            *byte = 0;
        }
    }

    pub fn set_boot_file(&mut self, value: &str) {
        let data = self.buffer.as_mut();
        data[field::FILE][..value.len()].copy_from_slice(value.as_bytes());
        for i in data[field::FILE][value.len()..].iter_mut() {
            *i = 0;
        }
    }

    pub fn set_sname(&mut self, value: &str) {
        let data = self.buffer.as_mut();
        data[field::SNAME][..value.len()].copy_from_slice(value.as_bytes());
        for i in data[field::SNAME][value.len()..].iter_mut() {
            *i = 0;
        }
    }

    /// Sets the `OpCode` for the packet.
    pub fn set_opcode(&mut self, value: OpCode) {
        let data = self.buffer.as_mut();
        data[field::OP] = value.into();
    }

    /// Sets the hardware address type (only ethernet is supported).
    pub fn set_hardware_type(&mut self, value: Hardware) {
        let data = self.buffer.as_mut();
        let number: u16 = value.into();
        assert!(number <= u16::from(u8::max_value())); // TODO: Replace with TryFrom when it's stable
        data[field::HTYPE] = number as u8;
    }

    /// Sets the hardware address length.
    ///
    /// Only ethernet is supported, so this field should be set to the value `6`.
    pub fn set_hardware_len(&mut self, value: u8) {
        self.buffer.as_mut()[field::HLEN] = value;
    }

    /// Sets the transaction ID.
    ///
    /// The transaction ID (called `xid` in the specification) is a random number used to
    /// associate messages and responses between client and server. The number is chosen by
    /// the client.
    pub fn set_transaction_id(&mut self, value: u32) {
        let field = &mut self.buffer.as_mut()[field::XID];
        NetworkEndian::write_u32(field, value)
    }

    /// Sets the ethernet address of the client.
    ///
    /// Sets the `chaddr` field.
    pub fn set_client_hardware_address(&mut self, value: EthernetAddress) {
        let field = &mut self.buffer.as_mut()[field::CHADDR];
        field[..core::mem::size_of::<EthernetAddress>()].copy_from_slice(value.as_bytes());
        for i in field[core::mem::size_of::<EthernetAddress>()..].iter_mut() {
            *i = 0;
        }
    }

    /// Sets the hops field.
    ///
    /// The `hops` field is set to zero by clients and optionally used by relay agents.
    pub fn set_hops(&mut self, value: u8) {
        self.buffer.as_mut()[field::HOPS] = value;
    }

    /// Sets the `secs` field.
    ///
    /// The secs field is filled by clients and describes the number of seconds elapsed
    /// since client began process.
    pub fn set_secs(&mut self, value: u16) {
        let field = &mut self.buffer.as_mut()[field::SECS];
        NetworkEndian::write_u16(field, value);
    }

    /// Sets the value of the `magic cookie` field in the DHCP options.
    ///
    /// This field should be always be `0x63825363`.
    pub fn set_magic_number(&mut self, value: u32) {
        let field = &mut self.buffer.as_mut()[field::MAGIC_NUMBER];
        NetworkEndian::write_u32(field, value);
    }

    /// Sets the Ipv4 address of the client.
    ///
    /// This corresponds to the `ciaddr` field in the DHCP specification. According to it,
    /// this field is “only filled in if client is in `BOUND`, `RENEW` or `REBINDING` state
    /// and can respond to ARP requests”.
    pub fn set_client_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::CIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    /// Sets the value of the `yiaddr` field.
    pub fn set_your_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::YIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    /// Sets the value of the `siaddr` field.
    pub fn set_server_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::SIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    /// Sets the value of the `giaddr` field.
    pub fn set_relay_agent_ip(&mut self, value: Ipv4Address) {
        let field = &mut self.buffer.as_mut()[field::GIADDR];
        field.copy_from_slice(value.as_bytes());
    }

    /// Sets the flags to the specified value.
    pub fn set_flags(&mut self, val: Flags) {
        let field = &mut self.buffer.as_mut()[field::FLAGS];
        NetworkEndian::write_u16(field, val.bits());
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    /// Return a pointer to the options.
    #[inline]
    pub fn options_mut(&mut self) -> Result<&mut [u8]> {
        let data = self.buffer.as_mut();
        data.get_mut(field::OPTIONS).ok_or(Error::Truncated)
    }
}

/// A high-level representation of a Dynamic Host Configuration Protocol packet.
///
/// DHCP messages have the following layout (see [RFC 2131](https://tools.ietf.org/html/rfc2131)
/// for details):
///
/// ```no_rust
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | message_type  | htype (N/A)   |   hlen (N/A)  |   hops        |
/// +---------------+---------------+---------------+---------------+
/// |                       transaction_id                          |
/// +-------------------------------+-------------------------------+
/// |           secs                |           flags               |
/// +-------------------------------+-------------------------------+
/// |                           client_ip                           |
/// +---------------------------------------------------------------+
/// |                            your_ip                            |
/// +---------------------------------------------------------------+
/// |                           server_ip                           |
/// +---------------------------------------------------------------+
/// |                        relay_agent_ip                         |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                    client_hardware_address                    |
/// |                                                               |
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          sname  (N/A)                         |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          file    (N/A)                        |
/// +---------------------------------------------------------------+
/// |                                                               |
/// |                          options                              |
/// +---------------------------------------------------------------+
/// ```
///
/// It is assumed that the access layer is Ethernet, so `htype` (the field representing the
/// hardware address type) is always set to `1`, and `hlen` (which represents the hardware address
/// length) is set to `6`.
///
/// The `options` field has a variable length.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr<'a> {
    /// This field is also known as `op` in the RFC. It indicates the type of DHCP message this
    /// packet represents.
    pub message_type: MessageType,
    /// This field is also known as `xid` in the RFC. It is a random number chosen by the client,
    /// used by the client and server to associate messages and responses between a client and a
    /// server.
    pub transaction_id: u32,
    /// seconds elapsed since client began address acquisition or renewal process
    /// the DHCPREQUEST message MUST use the same value in the DHCP message header's 'secs' field and be sent to the
    /// same IP broadcast address as the original DHCPDISCOVER message.
    pub secs: u16,
    /// This field is also known as `chaddr` in the RFC and for networks where the access layer is
    /// ethernet, it is the client MAC address.
    pub client_hardware_address: EthernetAddress,
    /// This field is also known as `ciaddr` in the RFC. It is only filled in if client is in
    /// BOUND, RENEW or REBINDING state and can respond to ARP requests.
    pub client_ip: Ipv4Address,
    /// This field is also known as `yiaddr` in the RFC.
    pub your_ip: Ipv4Address,
    /// This field is also known as `siaddr` in the RFC. It may be set by the server in DHCPOFFER
    /// and DHCPACK messages, and represent the address of the next server to use in bootstrap.
    pub server_ip: Ipv4Address,
    /// Boot file name, null terminated string; "generic"
    /// name or null in DHCPDISCOVER, fully qualified
    pub boot_file: Option<&'a str>,
    /// Optional server host name, null terminated string.
    pub sname: Option<&'a str>,
    /// Default gateway
    pub router: Option<Ipv4Address>,
    /// This field comes from a corresponding DhcpOption.
    pub subnet_mask: Option<Ipv4Address>,
    /// This field is also known as `giaddr` in the RFC. In order to allow DHCP clients on subnets
    /// not directly served by DHCP servers to communicate with DHCP servers, DHCP relay agents can
    /// be installed on these subnets. The DHCP client broadcasts on the local link; the relay
    /// agent receives the broadcast and transmits it to one or more DHCP servers using unicast.
    /// The relay agent stores its own IP address in the `relay_agent_ip` field of the DHCP packet.
    /// The DHCP server uses the `relay_agent_ip` to determine the subnet on which the relay agent
    /// received the broadcast, and allocates an IP address on that subnet. When the DHCP server
    /// replies to the client, it sends the reply to the `relay_agent_ip` address, again using
    /// unicast. The relay agent then retransmits the response on the local network
    pub relay_agent_ip: Ipv4Address,
    /// Broadcast flags. It can be set in DHCPDISCOVER, DHCPINFORM and DHCPREQUEST message if the
    /// client requires the response to be broadcasted.
    pub broadcast: bool,
    /// The "requested IP address" option. It can be used by clients in DHCPREQUEST or DHCPDISCOVER
    /// messages, or by servers in DHCPDECLINE messages.
    pub requested_ip: Option<Ipv4Address>,
    /// The "client identifier" option.
    ///
    /// The 'client identifier' is an opaque key, not to be interpreted by the server; for example,
    /// the 'client identifier' may contain a hardware address, identical to the contents of the
    /// 'chaddr' field, or it may contain another type of identifier, such as a DNS name.  The
    /// 'client identifier' chosen by a DHCP client MUST be unique to that client within the subnet
    /// to which the client is attached. If the client uses a 'client identifier' in one message,
    /// it MUST use that same identifier in all subsequent messages, to ensure that all servers
    /// correctly identify the client.
    pub client_identifier: Option<EthernetAddress>,
    /// The "server identifier" option. It is used both to identify a DHCP server
    /// in a DHCP message and as a destination address from clients to servers.
    pub server_identifier: Option<Ipv4Address>,
    /// The parameter request list informs the server about which configuration parameters
    /// the client is interested in.
    pub parameter_request_list: Option<&'a [u8]>,
    /// DNS servers
    pub dns_servers: Option<[Option<Ipv4Address>; MAX_DNS_SERVER_COUNT]>,
    /// The maximum size dhcp packet the interface can receive
    pub max_size: Option<u16>,
    /// The DHCP IP lease duration, specified in seconds.
    pub lease_duration: Option<u32>,
    /// Describes the pre-boot runtime environment(s) of the client machine.
    pub client_arch_list: Option<&'a [u8]>,
    /// Describe the client interface revision
    pub client_interface_id: Option<NetworkInterfaceVersion>,
    /// Globally Unique Identifier for PXE client
    pub client_machine_id: Option<MachineId<'a>>,
    /// The time offset field specifies the offset of the client's subnet in
    /// seconds from Coordinated Universal Time (UTC).
    pub time_offset: Option<u32>,
    /// A ascii string representing the vendor of the client
    pub vendor_class_id: Option<&'a str>,
}

impl<'a> Repr<'a> {
    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        let mut len = field::OPTIONS.start;
        // message type and end-of-options options
        len += 3 + 1;
        if self.requested_ip.is_some() {
            len += 6;
        }
        if self.client_identifier.is_some() {
            len += 9;
        }
        if self.server_identifier.is_some() {
            len += 6;
        }
        if self.max_size.is_some() {
            len += 4;
        }
        if self.router.is_some() {
            len += 6;
        }
        if self.subnet_mask.is_some() {
            len += 6;
        }
        if self.lease_duration.is_some() {
            len += 6;
        }
        if self.time_offset.is_some() {
            len += 6;
        }
        if self.client_interface_id.is_some() {
            len += 5;
        }
        if let Some(list) = self.client_machine_id {
            len += list.id.len() + 3;
        }
        if let Some(list) = self.client_arch_list {
            len += list.len() + 2;
        }
        if let Some(dns_servers) = self.dns_servers {
            len += 2;
            len += dns_servers.iter().flatten().count() * core::mem::size_of::<u32>();
        }
        if let Some(list) = self.parameter_request_list {
            len += list.len() + 2;
        }

        len
    }

    /// Parse a DHCP packet and return a high-level representation.
    pub fn parse<T>(packet: &Packet<&'a T>) -> Result<Self>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let transaction_id = packet.transaction_id();
        let client_hardware_address = packet.client_hardware_address();
        let client_ip = packet.client_ip();
        let your_ip = packet.your_ip();
        let server_ip = packet.server_ip();
        let relay_agent_ip = packet.relay_agent_ip();
        let sname = packet.get_sname().ok();
        let boot_file = packet.get_boot_file().ok();
        let secs = packet.secs();

        // only ethernet is supported right now
        match packet.hardware_type() {
            Hardware::Ethernet => {
                if packet.hardware_len() != 6 {
                    return Err(Error::Malformed);
                }
            }
            Hardware::Unknown(_) => return Err(Error::Unrecognized), // unimplemented
        }

        if packet.magic_number() != DHCP_MAGIC_NUMBER {
            return Err(Error::Malformed);
        }

        let mut message_type = Err(Error::Malformed);
        let mut requested_ip = None;
        let mut client_identifier = None;
        let mut server_identifier = None;
        let mut router = None;
        let mut subnet_mask = None;
        let mut parameter_request_list = None;
        let mut dns_servers = None;
        let mut max_size = None;
        let mut lease_duration = None;
        let mut time_offset = None;
        let mut client_arch_list = None;
        let mut client_interface_id = None;
        let mut client_machine_id = None;
        let mut vendor_class_id = None;

        let mut options = packet.options()?;
        while !options.is_empty() {
            let (next_options, option) = DhcpOption::parse(options)?;
            match option {
                DhcpOption::EndOfList => break,
                DhcpOption::Pad => {}
                DhcpOption::MessageType(value) => {
                    if value.opcode() == packet.opcode() {
                        message_type = Ok(value);
                    }
                }
                DhcpOption::ClientMachineId(list) => {
                    client_machine_id = Some(list);
                }
                DhcpOption::TimeOffset(offset) => {
                    time_offset = Some(offset);
                }
                DhcpOption::RequestedIp(ip) => {
                    requested_ip = Some(ip);
                }
                DhcpOption::ClientNetworkInterfaceId(id) => {
                    client_interface_id = Some(id);
                }
                DhcpOption::ClientArchTypeList(list) => {
                    client_arch_list = Some(list);
                }
                DhcpOption::VendorClassId(id) => {
                    vendor_class_id = Some(id);
                }
                DhcpOption::ClientIdentifier(eth_addr) => {
                    client_identifier = Some(eth_addr);
                }
                DhcpOption::ServerIdentifier(ip) => {
                    server_identifier = Some(ip);
                }
                DhcpOption::Router(ip) => {
                    router = Some(ip);
                }
                DhcpOption::SubnetMask(mask) => {
                    subnet_mask = Some(mask);
                }
                DhcpOption::MaximumDhcpMessageSize(size) => {
                    max_size = Some(size);
                }
                DhcpOption::IpLeaseTime(duration) => {
                    lease_duration = Some(duration);
                }
                DhcpOption::Other {
                    kind: field::OPT_PARAMETER_REQUEST_LIST,
                    data,
                } => {
                    parameter_request_list = Some(data);
                }
                DhcpOption::Other {
                    kind: field::OPT_DOMAIN_NAME_SERVER,
                    data,
                } => {
                    let mut servers = [None; MAX_DNS_SERVER_COUNT];
                    let chunk_size = 4;
                    for (server, chunk) in servers.iter_mut().zip(data.chunks(chunk_size)) {
                        if chunk.len() != chunk_size {
                            return Err(Error::Malformed);
                        }
                        *server = Some(Ipv4Address::from_bytes(chunk));
                    }
                    dns_servers = Some(servers);
                }
                DhcpOption::Other { .. } => {}
            }
            options = next_options;
        }

        let broadcast = packet.flags().contains(Flags::BROADCAST);

        Ok(Repr {
            secs,
            transaction_id,
            client_hardware_address,
            client_ip,
            your_ip,
            sname,
            boot_file,
            server_ip,
            relay_agent_ip,
            broadcast,
            requested_ip,
            server_identifier,
            router,
            subnet_mask,
            client_identifier,
            parameter_request_list,
            dns_servers,
            max_size,
            lease_duration,
            time_offset,
            client_arch_list,
            client_interface_id,
            client_machine_id,
            vendor_class_id,
            message_type: message_type?,
        })
    }

    /// Emit a high-level representation into a Dynamic Host
    /// Configuration Protocol packet.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>) -> Result<()>
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        if let Some(sname) = self.sname {
            if sname.len() + 1 < field::SNAME.len() {
                packet.set_sname(sname);
            } else {
                return Err(Error::Illegal);
            }
        } else {
            packet.set_sname(
                core::str::from_utf8(&[0; field::SNAME.end - field::SNAME.start]).unwrap(),
            );
        }

        if let Some(boot_file) = self.boot_file {
            if boot_file.len() + 1 < field::FILE.len() {
                packet.set_boot_file(boot_file);
            } else {
                return Err(Error::Illegal);
            }
        } else {
            packet.set_boot_file(
                core::str::from_utf8(&[0; field::FILE.end - field::FILE.start]).unwrap(),
            );
        }
        packet.set_opcode(self.message_type.opcode());
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_hardware_len(6);
        packet.set_transaction_id(self.transaction_id);
        packet.set_client_hardware_address(self.client_hardware_address);
        packet.set_hops(0);
        packet.set_secs(self.secs);
        packet.set_magic_number(0x63825363);
        packet.set_client_ip(self.client_ip);
        packet.set_your_ip(self.your_ip);
        packet.set_server_ip(self.server_ip);
        packet.set_relay_agent_ip(self.relay_agent_ip);

        let mut flags = Flags::empty();
        if self.broadcast {
            flags |= Flags::BROADCAST;
        }
        packet.set_flags(flags);

        {
            let mut options = packet.options_mut()?;
            options = DhcpOption::MessageType(self.message_type).emit(options);
            if let Some(eth_addr) = self.client_identifier {
                options = DhcpOption::ClientIdentifier(eth_addr).emit(options);
            }
            if let Some(ip) = self.server_identifier {
                options = DhcpOption::ServerIdentifier(ip).emit(options);
            }
            if let Some(ip) = self.router {
                options = DhcpOption::Router(ip).emit(options);
            }
            if let Some(ip) = self.subnet_mask {
                options = DhcpOption::SubnetMask(ip).emit(options);
            }
            if let Some(ip) = self.requested_ip {
                options = DhcpOption::RequestedIp(ip).emit(options);
            }
            if let Some(size) = self.max_size {
                options = DhcpOption::MaximumDhcpMessageSize(size).emit(options);
            }
            if let Some(client_arch_list) = self.client_arch_list {
                options = DhcpOption::ClientArchTypeList(client_arch_list).emit(options);
            }
            if let Some(client_machine_id) = self.client_machine_id {
                options = DhcpOption::ClientMachineId(client_machine_id).emit(options);
            }
            if let Some(vendor_class_id) = self.vendor_class_id {
                options = DhcpOption::VendorClassId(vendor_class_id).emit(options);
            }
            if let Some(time_offset) = self.time_offset {
                options = DhcpOption::TimeOffset(time_offset).emit(options);
            }
            if let Some(client_interface_id) = self.client_interface_id {
                options = DhcpOption::ClientNetworkInterfaceId(client_interface_id).emit(options);
            }
            if let Some(duration) = self.lease_duration {
                options = DhcpOption::IpLeaseTime(duration).emit(options);
            }
            if let Some(dns_servers) = self.dns_servers {
                const IP_SIZE: usize = core::mem::size_of::<u32>();
                let mut servers = [0; MAX_DNS_SERVER_COUNT * IP_SIZE];

                let data_len = dns_servers
                    .iter()
                    .flatten()
                    .enumerate()
                    .inspect(|(i, ip)| {
                        servers[(i * IP_SIZE)..((i + 1) * IP_SIZE)].copy_from_slice(ip.as_bytes());
                    })
                    .count()
                    * IP_SIZE;
                let option = DhcpOption::Other {
                    kind: field::OPT_DOMAIN_NAME_SERVER,
                    data: &servers[..data_len],
                };
                options = option.emit(options);
            }
            if let Some(list) = self.parameter_request_list {
                options = DhcpOption::Other {
                    kind: field::OPT_PARAMETER_REQUEST_LIST,
                    data: list,
                }
                .emit(options);
            }
            DhcpOption::EndOfList.emit(options);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::Ipv4Address;

    const MAGIC_COOKIE: u32 = 0x63825363;

    /* Frame (548 bytes) */
    static PXE_DISCOVER_BYTES: &[u8] = &[
        0x01, 0x01, 0x06, 0x00, 0x2f, 0x91, 0xf7, 0xfd, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
        0x82, 0x01, 0xfc, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
        0x35, 0x01, 0x01, 0x37, 0x24, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0b, 0x0c, 0x0d, 0x0f,
        0x10, 0x11, 0x12, 0x16, 0x17, 0x1c, 0x28, 0x29, 0x2a, 0x2b, 0x32, 0x33, 0x36, 0x3a, 0x3b,
        0x3c, 0x42, 0x43, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x39, 0x02, 0x04, 0xec,
        0x61, 0x11, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07,
        0x00, 0x08, 0x00, 0x09, 0x5d, 0x02, 0x00, 0x00, 0x5e, 0x03, 0x01, 0x02, 0x01, 0x3c, 0x20,
        0x50, 0x58, 0x45, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x3a, 0x41, 0x72, 0x63, 0x68, 0x3a,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x3a, 0x55, 0x4e, 0x44, 0x49, 0x3a, 0x30, 0x30, 0x32, 0x30,
        0x30, 0x31, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    static DISCOVER_BYTES: &[u8] = &[
        0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
        0x82, 0x01, 0xfc, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
        0x35, 0x01, 0x01, 0x3d, 0x07, 0x01, 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42, 0x32, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x39, 0x2, 0x5, 0xdc, 0x37, 0x04, 0x01, 0x03, 0x06, 0x2a, 0xff, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    static ACK_DNS_SERVER_BYTES: &[u8] = &[
        0x02, 0x01, 0x06, 0x00, 0xcc, 0x34, 0x75, 0xab, 0x00, 0x00, 0x80, 0x00, 0x0a, 0xff, 0x06,
        0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x06, 0xfe, 0x34, 0x17,
        0xeb, 0xc9, 0xaa, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
        0x35, 0x01, 0x05, 0x36, 0x04, 0xa3, 0x01, 0x4a, 0x16, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00,
        0x2b, 0x05, 0xdc, 0x03, 0x4e, 0x41, 0x50, 0x0f, 0x15, 0x6e, 0x61, 0x74, 0x2e, 0x70, 0x68,
        0x79, 0x73, 0x69, 0x63, 0x73, 0x2e, 0x6f, 0x78, 0x2e, 0x61, 0x63, 0x2e, 0x75, 0x6b, 0x00,
        0x03, 0x04, 0x0a, 0xff, 0x06, 0xfe, 0x06, 0x10, 0xa3, 0x01, 0x4a, 0x06, 0xa3, 0x01, 0x4a,
        0x07, 0xa3, 0x01, 0x4a, 0x03, 0xa3, 0x01, 0x4a, 0x04, 0x2c, 0x10, 0xa3, 0x01, 0x4a, 0x03,
        0xa3, 0x01, 0x4a, 0x04, 0xa3, 0x01, 0x4a, 0x06, 0xa3, 0x01, 0x4a, 0x07, 0x2e, 0x01, 0x08,
        0xff,
    ];

    static ACK_LEASE_TIME_BYTES: &[u8] = &[
        0x02, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0a, 0x22, 0x10, 0x0b, 0x0a, 0x22, 0x10, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x04, 0x91,
        0x62, 0xd2, 0xa8, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
        0x35, 0x01, 0x05, 0x36, 0x04, 0x0a, 0x22, 0x10, 0x0a, 0x33, 0x04, 0x00, 0x00, 0x02, 0x56,
        0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0x0a, 0x22, 0x10, 0x0a, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const IP_NULL: Ipv4Address = Ipv4Address([0, 0, 0, 0]);
    const CLIENT_MAC: EthernetAddress = EthernetAddress([0x0, 0x0b, 0x82, 0x01, 0xfc, 0x42]);
    const DHCP_SIZE: u16 = 1500;

    #[test]
    fn test_construct_pxe_discover() {
        let mut bytes = vec![0xa5; 360];
        assert_eq!(bytes.len(), PXE_DISCOVER_BYTES.len());
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_magic_number(MAGIC_COOKIE);
        packet.set_sname_and_boot_file_to_zero();
        packet.set_opcode(OpCode::Request);
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_hardware_len(6);
        packet.set_hops(0);
        packet.set_transaction_id(0x2f91f7fd);
        packet.set_secs(4);
        packet.set_flags(Flags::BROADCAST);
        packet.set_client_ip(IP_NULL);
        packet.set_your_ip(IP_NULL);
        packet.set_server_ip(IP_NULL);
        packet.set_relay_agent_ip(IP_NULL);
        packet.set_client_hardware_address(CLIENT_MAC);

        {
            let mut options = packet.options_mut().unwrap();
            options = DhcpOption::MessageType(MessageType::Discover).emit(options);
            options = DhcpOption::Other {
                kind: field::OPT_PARAMETER_REQUEST_LIST,
                data: &[
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0b, 0x0c, 0x0d, 0x0f, 0x10, 0x11, 0x12,
                    0x16, 0x17, 0x1c, 0x28, 0x29, 0x2a, 0x2b, 0x32, 0x33, 0x36, 0x3a, 0x3b, 0x3c,
                    0x42, 0x43, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                ],
            }
            .emit(options);
            options = DhcpOption::MaximumDhcpMessageSize(1260).emit(options);
            options = DhcpOption::ClientMachineId(MachineId {
                id_type: MachineIdType::Guid,
                id: &[
                    0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00,
                    0x08, 0x00, 0x09,
                ],
            })
            .emit(options);
            options =
                DhcpOption::ClientArchTypeList(&(ClientArchType::X86Bios as u16).to_be_bytes())
                    .emit(options);
            options = DhcpOption::ClientNetworkInterfaceId(NetworkInterfaceVersion {
                interface_type: NetworkInterfaceType::Undi,
                major: 2,
                minor: 1,
            })
            .emit(options);
            options = DhcpOption::VendorClassId("PXEClient:Arch:00000:UNDI:002001").emit(options);

            DhcpOption::EndOfList.emit(options);
        }

        let packet = &mut packet.into_inner()[..];
        for byte in &mut packet[348..360] {
            *byte = 0; // padding bytes
        }

        assert_eq!(packet, PXE_DISCOVER_BYTES);
    }

    #[test]
    fn test_deconstruct_discover_pxe() {
        use crate::wire::dhcpv4::field::*;
        let packet = Packet::new_checked(PXE_DISCOVER_BYTES).unwrap();
        assert_eq!(packet.magic_number(), MAGIC_COOKIE);
        assert_eq!(packet.opcode(), OpCode::Request);
        assert_eq!(packet.hardware_type(), Hardware::Ethernet);
        assert_eq!(packet.hardware_len(), 6);
        assert_eq!(packet.hops(), 0);
        assert_eq!(packet.transaction_id(), 0x2f91f7fd);
        assert_eq!(packet.secs(), 4);
        assert_eq!(packet.client_ip(), IP_NULL);
        assert_eq!(packet.your_ip(), IP_NULL);
        assert_eq!(packet.server_ip(), IP_NULL);
        assert_eq!(packet.relay_agent_ip(), IP_NULL);
        assert_eq!(packet.client_hardware_address(), CLIENT_MAC);
        let options = packet.options().unwrap();
        assert_eq!(options.len(), 3 + 38 + 4 + 19 + 4 + 5 + 34 + 1 + 12);

        let (options, message_type) = DhcpOption::parse(options).unwrap();
        assert_eq!(message_type, DhcpOption::MessageType(MessageType::Discover));
        assert_eq!(options.len(), 38 + 4 + 19 + 4 + 5 + 34 + 1 + 12);

        let (options, message_type) = DhcpOption::parse(options).unwrap();
        match message_type {
            DhcpOption::Other {
                kind: OPT_PARAMETER_REQUEST_LIST,
                data: _,
            } => (),
            _ => panic!("Expected parameter request list here"),
        }
        assert_eq!(options.len(), 4 + 19 + 4 + 5 + 34 + 1 + 12);

        let (options, msg_size) = DhcpOption::parse(options).unwrap();
        assert_eq!(msg_size, DhcpOption::MaximumDhcpMessageSize(1260));
        assert_eq!(options.len(), 19 + 4 + 5 + 34 + 1 + 12);

        let (options, msg_size) = DhcpOption::parse(options).unwrap();
        assert_eq!(
            msg_size,
            DhcpOption::ClientMachineId(MachineId {
                id_type: MachineIdType::Guid,
                id: &[
                    0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00,
                    0x08, 0x00, 0x09
                ]
            })
        );
        assert_eq!(options.len(), 4 + 5 + 34 + 1 + 12);

        let (options, msg_size) = DhcpOption::parse(options).unwrap();
        assert_eq!(msg_size, DhcpOption::ClientArchTypeList(&[0x00, 0x00]));
        assert_eq!(options.len(), 5 + 34 + 1 + 12);

        let (options, msg_size) = DhcpOption::parse(options).unwrap();
        assert_eq!(
            msg_size,
            DhcpOption::ClientNetworkInterfaceId(NetworkInterfaceVersion {
                interface_type: NetworkInterfaceType::Undi,
                major: 2,
                minor: 1
            })
        );
        assert_eq!(options.len(), 34 + 1 + 12);

        let (options, msg_size) = DhcpOption::parse(options).unwrap();
        assert_eq!(
            msg_size,
            DhcpOption::VendorClassId("PXEClient:Arch:00000:UNDI:002001")
        );
        assert_eq!(options.len(), 1 + 12);

        let (options, client_id) = DhcpOption::parse(options).unwrap();
        assert_eq!(client_id, DhcpOption::EndOfList);
        assert_eq!(options.len(), 12); // padding
    }

    #[test]
    fn test_deconstruct_discover() {
        let packet = Packet::new_unchecked(DISCOVER_BYTES);
        assert_eq!(packet.magic_number(), MAGIC_COOKIE);
        assert_eq!(packet.opcode(), OpCode::Request);
        assert_eq!(packet.hardware_type(), Hardware::Ethernet);
        assert_eq!(packet.hardware_len(), 6);
        assert_eq!(packet.hops(), 0);
        assert_eq!(packet.transaction_id(), 0x3d1d);
        assert_eq!(packet.secs(), 0);
        assert_eq!(packet.client_ip(), IP_NULL);
        assert_eq!(packet.your_ip(), IP_NULL);
        assert_eq!(packet.server_ip(), IP_NULL);
        assert_eq!(packet.relay_agent_ip(), IP_NULL);
        assert_eq!(packet.client_hardware_address(), CLIENT_MAC);
        let options = packet.options().unwrap();
        assert_eq!(options.len(), 3 + 9 + 6 + 4 + 6 + 1 + 7);

        let (options, message_type) = DhcpOption::parse(options).unwrap();
        assert_eq!(message_type, DhcpOption::MessageType(MessageType::Discover));
        assert_eq!(options.len(), 9 + 6 + 4 + 6 + 1 + 7);

        let (options, client_id) = DhcpOption::parse(options).unwrap();
        assert_eq!(client_id, DhcpOption::ClientIdentifier(CLIENT_MAC));
        assert_eq!(options.len(), 6 + 4 + 6 + 1 + 7);

        let (options, client_id) = DhcpOption::parse(options).unwrap();
        assert_eq!(client_id, DhcpOption::RequestedIp(IP_NULL));
        assert_eq!(options.len(), 4 + 6 + 1 + 7);

        let (options, msg_size) = DhcpOption::parse(options).unwrap();
        assert_eq!(msg_size, DhcpOption::MaximumDhcpMessageSize(DHCP_SIZE));
        assert_eq!(options.len(), 6 + 1 + 7);

        let (options, client_id) = DhcpOption::parse(options).unwrap();
        assert_eq!(
            client_id,
            DhcpOption::Other {
                kind: field::OPT_PARAMETER_REQUEST_LIST,
                data: &[1, 3, 6, 42]
            }
        );
        assert_eq!(options.len(), 1 + 7);

        let (options, client_id) = DhcpOption::parse(options).unwrap();
        assert_eq!(client_id, DhcpOption::EndOfList);
        assert_eq!(options.len(), 7); // padding
    }

    #[test]
    fn test_construct_discover() {
        let mut bytes = vec![0xa5; 276];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_magic_number(MAGIC_COOKIE);
        packet.set_sname_and_boot_file_to_zero();
        packet.set_opcode(OpCode::Request);
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_hardware_len(6);
        packet.set_hops(0);
        packet.set_transaction_id(0x3d1d);
        packet.set_secs(0);
        packet.set_flags(Flags::empty());
        packet.set_client_ip(IP_NULL);
        packet.set_your_ip(IP_NULL);
        packet.set_server_ip(IP_NULL);
        packet.set_relay_agent_ip(IP_NULL);
        packet.set_client_hardware_address(CLIENT_MAC);

        {
            let mut options = packet.options_mut().unwrap();
            options = DhcpOption::MessageType(MessageType::Discover).emit(options);
            options = DhcpOption::ClientIdentifier(CLIENT_MAC).emit(options);
            options = DhcpOption::RequestedIp(IP_NULL).emit(options);
            options = DhcpOption::MaximumDhcpMessageSize(DHCP_SIZE).emit(options);
            let option = DhcpOption::Other {
                kind: field::OPT_PARAMETER_REQUEST_LIST,
                data: &[1, 3, 6, 42],
            };
            options = option.emit(options);
            DhcpOption::EndOfList.emit(options);
        }

        let packet = &mut packet.into_inner()[..];
        for byte in &mut packet[269..276] {
            *byte = 0; // padding bytes
        }

        assert_eq!(packet, DISCOVER_BYTES);
    }

    fn offer_repr() -> Repr<'static> {
        Repr {
            message_type: MessageType::Offer,
            transaction_id: 0x3d1d,
            client_hardware_address: CLIENT_MAC,
            sname: None,
            boot_file: None,
            client_ip: IP_NULL,
            your_ip: IP_NULL,
            server_ip: IP_NULL,
            router: Some(IP_NULL),
            subnet_mask: Some(IP_NULL),
            relay_agent_ip: IP_NULL,
            secs: 0,
            broadcast: false,
            requested_ip: None,
            client_identifier: Some(CLIENT_MAC),
            server_identifier: None,
            parameter_request_list: None,
            dns_servers: None,
            max_size: None,
            lease_duration: Some(0xffff_ffff), // Infinite lease
            time_offset: None,
            client_arch_list: None,
            client_interface_id: None,
            client_machine_id: None,
            vendor_class_id: None,
        }
    }

    fn discover_repr() -> Repr<'static> {
        Repr {
            message_type: MessageType::Discover,
            transaction_id: 0x3d1d,
            client_hardware_address: CLIENT_MAC,
            boot_file: None,
            sname: None,
            client_ip: IP_NULL,
            your_ip: IP_NULL,
            server_ip: IP_NULL,
            router: None,
            subnet_mask: None,
            relay_agent_ip: IP_NULL,
            broadcast: false,
            secs: 0,
            max_size: Some(DHCP_SIZE),
            lease_duration: None,
            requested_ip: Some(IP_NULL),
            client_identifier: Some(CLIENT_MAC),
            server_identifier: None,
            parameter_request_list: Some(&[1, 3, 6, 42]),
            dns_servers: None,
            time_offset: None,
            client_arch_list: None,
            client_interface_id: None,
            client_machine_id: None,
            vendor_class_id: None,
        }
    }

    #[test]
    fn test_parse_discover() {
        let packet = Packet::new_unchecked(DISCOVER_BYTES);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, discover_repr());
    }

    #[test]
    fn test_emit_discover() {
        let repr = discover_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet).unwrap();
        let packet = &packet.into_inner()[..];
        let packet_len = packet.len();
        assert_eq!(packet, &DISCOVER_BYTES[..packet_len]);
        for byte in &DISCOVER_BYTES[packet_len..] {
            assert_eq!(*byte, 0); // padding bytes
        }
    }

    #[test]
    fn test_emit_offer() {
        let repr = offer_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet).unwrap();
    }

    #[test]
    fn test_emit_offer_dns() {
        let repr = {
            let mut repr = offer_repr();
            repr.dns_servers = Some([
                Some(Ipv4Address([163, 1, 74, 6])),
                Some(Ipv4Address([163, 1, 74, 7])),
                Some(Ipv4Address([163, 1, 74, 3])),
            ]);
            repr
        };
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet).unwrap();

        let packet = Packet::new_unchecked(&bytes);
        let repr_parsed = Repr::parse(&packet).unwrap();

        assert_eq!(
            repr_parsed.dns_servers,
            Some([
                Some(Ipv4Address([163, 1, 74, 6])),
                Some(Ipv4Address([163, 1, 74, 7])),
                Some(Ipv4Address([163, 1, 74, 3]))
            ])
        );
    }

    #[test]
    fn test_emit_dhcp_option() {
        static DATA: &[u8] = &[1, 3, 6];
        let mut bytes = vec![0xa5; 5];
        let dhcp_option = DhcpOption::Other {
            kind: field::OPT_PARAMETER_REQUEST_LIST,
            data: DATA,
        };
        {
            let rest = dhcp_option.emit(&mut bytes);
            assert_eq!(rest.len(), 0);
        }
        assert_eq!(
            &bytes[0..2],
            &[field::OPT_PARAMETER_REQUEST_LIST, DATA.len() as u8]
        );
        assert_eq!(&bytes[2..], DATA);
    }

    #[test]
    fn test_parse_ack_dns_servers() {
        let packet = Packet::new_unchecked(ACK_DNS_SERVER_BYTES);
        let repr = Repr::parse(&packet).unwrap();

        // The packet described by ACK_BYTES advertises 4 DNS servers
        // Here we ensure that we correctly parse the first 3 into our fixed
        // length-3 array (see issue #305)
        assert_eq!(
            repr.dns_servers,
            Some([
                Some(Ipv4Address([163, 1, 74, 6])),
                Some(Ipv4Address([163, 1, 74, 7])),
                Some(Ipv4Address([163, 1, 74, 3]))
            ])
        );
    }

    #[test]
    fn test_parse_ack_lease_duration() {
        let packet = Packet::new_unchecked(ACK_LEASE_TIME_BYTES);
        let repr = Repr::parse(&packet).unwrap();

        // Verify that the lease time in the ACK is properly parsed. The packet contains a lease
        // duration of 598s.
        assert_eq!(repr.lease_duration, Some(598));
    }
}
