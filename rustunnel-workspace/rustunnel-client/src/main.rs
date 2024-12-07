use rustunnel_lib::dns::{create_tcp_session, get_resolver};

fn main() {
    println!("Hello, world!");
    let host = "n.com";
    let port = 80;
    let domain = "natounet.com";

    create_tcp_session(host, port, domain, &get_resolver());
}
