use std::io;

use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let wait = vec![
        tokio::spawn(run_server(9997)),
        tokio::spawn(run_server(9998)),
        tokio::spawn(run_server(9999)),
    ];

    for thread in wait {
        thread.await.expect("server failed").unwrap();
    }
}

async fn run_server(port: u16) -> io::Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let socket = UdpSocket::bind(&addr).await?;
    println!("Listening on {}", addr);

    let mut buf = [0; 4];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        println!("[Port={}] received {} bytes from {}", port, len, addr);
        println!("[Port={}] content: {}", port, String::from_utf8_lossy(&buf))
    }
}