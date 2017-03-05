use core::str::FromStr;
use core::result;
use wire::{EthernetAddress, IpAddress, Ipv4Address};

type Result<T> = result::Result<T, ()>;

struct Parser<'a> {
    data: &'a [u8],
    pos:  usize
}

impl<'a> Parser<'a> {
    fn new(data: &'a str) -> Parser<'a> {
        Parser {
            data: data.as_bytes(),
            pos:  0
        }
    }

    fn advance(&mut self) -> Result<u8> {
        match self.data.get(self.pos) {
            Some(&chr) => {
                self.pos += 1;
                Ok(chr)
            }
            None => Err(())
        }
    }

    fn try<F, T>(&mut self, f: F) -> Option<T>
            where F: FnOnce(&mut Parser<'a>) -> Result<T> {
        let pos = self.pos;
        match f(self) {
            Ok(res) => Some(res),
            Err(()) => {
                self.pos = pos;
                None
            }
        }
    }

    fn accept_eof(&mut self) -> Result<()> {
        if self.data.len() == self.pos {
            Ok(())
        } else {
            Err(())
        }
    }

    fn until_eof<F, T>(&mut self, f: F) -> Result<T>
            where F: FnOnce(&mut Parser<'a>) -> Result<T> {
        let res = f(self)?;
        self.accept_eof()?;
        Ok(res)
    }

    fn accept_char(&mut self, chr: u8) -> Result<()> {
        if self.advance()? == chr {
            Ok(())
        } else {
            Err(())
        }
    }

    fn accept_digit(&mut self, hex: bool) -> Result<u8> {
        let digit = self.advance()?;
        if digit >= b'0' && digit <= b'9' {
            Ok(digit - b'0')
        } else if hex && digit >= b'a' && digit <= b'f' {
            Ok(digit - b'a' + 10)
        } else if hex && digit >= b'A' && digit <= b'F' {
            Ok(digit - b'A' + 10)
        } else {
            Err(())
        }
    }

    fn accept_number(&mut self, max_digits: usize, max_value: u32,
                     hex: bool) -> Result<u32> {
        let mut value = self.accept_digit(hex)? as u32;
        for _ in 1..max_digits {
            match self.try(|p| p.accept_digit(hex)) {
                Some(digit) => {
                    value *= if hex { 16 } else { 10 };
                    value += digit as u32;
                }
                None => break
            }
        }
        if value < max_value {
            Ok(value)
        } else {
            Err(())
        }
    }

    fn accept_mac_joined_with(&mut self, separator: u8) -> Result<EthernetAddress> {
        let mut octets = [0u8; 6];
        for n in 0..6 {
            octets[n] = self.accept_number(2, 0x100, true)? as u8;
            if n != 5 {
                self.accept_char(separator)?;
            }
        }
        Ok(EthernetAddress(octets))
    }

    fn accept_mac(&mut self) -> Result<EthernetAddress> {
        if let Some(mac) = self.try(|p| p.accept_mac_joined_with(b'-')) {
            return Ok(mac)
        }
        if let Some(mac) = self.try(|p| p.accept_mac_joined_with(b':')) {
            return Ok(mac)
        }
        Err(())
    }

    fn accept_ipv4(&mut self) -> Result<Ipv4Address> {
        let mut octets = [0u8; 4];
        for n in 0..4 {
            octets[n] = self.accept_number(3, 0x100, false)? as u8;
            if n != 3 {
                self.accept_char(b'.')?;
            }
        }
        Ok(Ipv4Address(octets))
    }

    fn accept_ip(&mut self) -> Result<IpAddress> {
        if let Some(()) = self.try(|p| p.accept_eof()) {
            return Ok(IpAddress::Unspecified)
        }
        if let Some(ipv4) = self.try(|p| p.accept_ipv4()) {
            return Ok(IpAddress::Ipv4(ipv4))
        }
        Err(())
    }
}

impl FromStr for EthernetAddress {
    type Err = ();

    /// Parse a string representation of an Ethernet address.
    fn from_str(s: &str) -> Result<EthernetAddress> {
        Parser::new(s).until_eof(|p| p.accept_mac())
    }
}

impl FromStr for Ipv4Address {
    type Err = ();

    /// Parse a string representation of an IPv4 address.
    fn from_str(s: &str) -> Result<Ipv4Address> {
        Parser::new(s).until_eof(|p| p.accept_ipv4())
    }
}

impl FromStr for IpAddress {
    type Err = ();

    /// Parse a string representation of an IPv4 address.
    fn from_str(s: &str) -> Result<IpAddress> {
        Parser::new(s).until_eof(|p| p.accept_ip())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mac() {
        assert_eq!(EthernetAddress::from_str(""), Err(()));
        assert_eq!(EthernetAddress::from_str("02:00:00:00:00:00"),
                   Ok(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x00])));
        assert_eq!(EthernetAddress::from_str("01:23:45:67:89:ab"),
                   Ok(EthernetAddress([0x01, 0x23, 0x45, 0x67, 0x89, 0xab])));
        assert_eq!(EthernetAddress::from_str("cd:ef:10:00:00:00"),
                   Ok(EthernetAddress([0xcd, 0xef, 0x10, 0x00, 0x00, 0x00])));
        assert_eq!(EthernetAddress::from_str("00:00:00:ab:cd:ef"),
                   Ok(EthernetAddress([0x00, 0x00, 0x00, 0xab, 0xcd, 0xef])));
        assert_eq!(EthernetAddress::from_str("00-00-00-ab-cd-ef"),
                   Ok(EthernetAddress([0x00, 0x00, 0x00, 0xab, 0xcd, 0xef])));
        assert_eq!(EthernetAddress::from_str("AB-CD-EF-00-00-00"),
                   Ok(EthernetAddress([0xab, 0xcd, 0xef, 0x00, 0x00, 0x00])));
        assert_eq!(EthernetAddress::from_str("100:00:00:00:00:00"), Err(()));
        assert_eq!(EthernetAddress::from_str("002:00:00:00:00:00"), Err(()));
        assert_eq!(EthernetAddress::from_str("02:00:00:00:00:000"), Err(()));
        assert_eq!(EthernetAddress::from_str("02:00:00:00:00:0x"), Err(()));
    }

    #[test]
    fn test_ipv4() {
        assert_eq!(Ipv4Address::from_str(""), Err(()));
        assert_eq!(Ipv4Address::from_str("1.2.3.4"),
                   Ok(Ipv4Address([1, 2, 3, 4])));
        assert_eq!(Ipv4Address::from_str("001.2.3.4"),
                   Ok(Ipv4Address([1, 2, 3, 4])));
        assert_eq!(Ipv4Address::from_str("0001.2.3.4"), Err(()));
        assert_eq!(Ipv4Address::from_str("999.2.3.4"), Err(()));
        assert_eq!(Ipv4Address::from_str("1.2.3.4.5"), Err(()));
        assert_eq!(Ipv4Address::from_str("1.2.3"), Err(()));
        assert_eq!(Ipv4Address::from_str("1.2.3."), Err(()));
        assert_eq!(Ipv4Address::from_str("1.2.3.4."), Err(()));
    }

    #[test]
    fn test_ip() {
        assert_eq!(IpAddress::from_str(""),
                   Ok(IpAddress::Unspecified));
        assert_eq!(IpAddress::from_str("1.2.3.4"),
                   Ok(IpAddress::Ipv4(Ipv4Address([1, 2, 3, 4]))));
        assert_eq!(IpAddress::from_str("x"), Err(()));
    }
}
