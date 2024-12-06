use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Clone, Debug)]
pub struct Options {
    /// UDP socket to listen on.
    #[clap(long, short, default_value = "0.0.0.0:1053", env = "RUSTUNNEL_UDP")]
    pub udp: Vec<SocketAddr>,

    /// Domain name
    #[clap(long, short, env = "RUSTUNNEL_DOMAIN")]
    pub domain: String,
}
