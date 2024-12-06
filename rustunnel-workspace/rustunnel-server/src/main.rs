mod handler;
mod options;
use clap::Parser;
use handler::Handler;
use hickory_server::ServerFuture;
use options::Options;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let options = Options::parse();
    let handler = Handler::from_options(&options);

    println!("Starting the DNS server...");

    println!("Domain set to {}", options.domain);
    // create DNS server
    let mut server = ServerFuture::new(handler);

    // register UDP listeners
    for udp in &options.udp {
        match UdpSocket::bind(udp).await {
            Ok(sock) => {
                println!("UDP Socket listening on {}", sock.local_addr().unwrap());
                server.register_socket(sock)
            }
            Err(e) => {
                eprintln!("Error binding socket: {}", e);
                return Err(());
            }
        }
    }
    println!("DNS server successfully started");

    // run DNS server
    match server.block_until_done().await {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Server error: {}", e);
            Err(())
        }
    }
}
