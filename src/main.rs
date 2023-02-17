extern crate clap;

use std::net::{IpAddr, TcpStream, SocketAddr};
use std::time::Duration;
use clap::{Arg, App};

const COMMON_PORTS: [u16; 98] = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 119, 123, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445,
    465, 514, 515, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1521, 1702, 1723, 2049, 2082, 2083, 2181, 2222,
    3128, 3306, 3389, 3690, 4333, 4444, 4662, 4672, 4899, 5000, 5432, 5632, 5900, 5938, 5984, 6000, 6001, 6379,
    6667, 7001, 7002, 8000, 8005, 8008, 8080, 8081, 8443, 8888, 9000, 9042, 9050, 9092, 9200, 9418, 9999, 10000,
    11211, 15672, 27017, 27018, 27019, 28017, 50000, 50070, 50075, 50090, 50095, 60010, 60030, 7001, 7002, 7199,
    8888, 9200, 9300,
];

fn scan_port(ip: IpAddr, port: &u16, timeout: Duration) -> bool {
    let socket_addr_str = format!("{}:{}", ip, port);
    let socket_addr = socket_addr_str.parse::<SocketAddr>().unwrap();
    TcpStream::connect_timeout(&socket_addr, timeout).is_ok()
}

fn main() {
    let timeout = Duration::from_secs(3);

    let matches = App::new("Port Scanner")
        .version("1.0")
        .author("Drew Maczugowski")
        .about("Scans for open ports on a remote host")
        .arg(Arg::with_name("ADDRESS")
            .help("Sets the target IP address or domain name")
            .required(true)
            .index(1))
        .arg(Arg::with_name("common-ports")
            .short('c')
            .long("common-ports")
            .help("Scans only commonly used ports"))
        .get_matches();

    let target_ip = matches.value_of("ADDRESS").unwrap();
    let binding = Vec::from_iter(1..=65535);
    let ports = match matches.is_present("common-ports") {
        true => COMMON_PORTS.as_slice(),
        false => binding.as_slice(),
    };

    for port in ports {
        if scan_port(target_ip.parse().unwrap(), port, timeout) {
            println!("Port {} is open", port);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_port_open() {
        assert!(scan_port("127.0.0.1".parse().unwrap(), 80, Duration::from_secs(3)));
    }

    #[test]
    fn test_scan_port_closed() {
        assert!(!scan_port("127.0.0.1".parse().unwrap(), 9999, Duration::from_secs(3)));
    }
}
