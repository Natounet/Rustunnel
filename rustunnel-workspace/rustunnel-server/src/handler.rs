use crate::options::Options;
use base32::Alphabet;
use rustunnel_lib::utils::{self, decode_base32};

use hickory_server::{
    authority::MessageResponseBuilder,
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    AsyncResolver,
};

use std::io::{Read, Write};

use hickory_proto::rr::{rdata::TXT, LowerName, Name, RData, Record};

use std::{str::FromStr, sync::Arc};

use std::{collections::HashMap, net::TcpStream, sync::Mutex};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid OpCode {0:}")]
    InvalidOpCode(OpCode),
    #[error("Invalid MessageType {0:}")]
    InvalidMessageType(MessageType),
    #[error("Invalid Zone {0:}")]
    InvalidZone(LowerName),
    #[error("IO error: {0:}")]
    Io(#[from] std::io::Error),
    #[error("Resolver error: {0:}")]
    ResolverError(#[from] hickory_resolver::error::ResolveError),
}

/// DNS Request Handler
#[derive(Clone, Debug)]
pub struct Handler {
    pub root_zone: LowerName,
    pub test_zone: LowerName,

    // Hashmap pour stocker les sockets ouverts
    pub sockets: Arc<Mutex<HashMap<u16, TcpStream>>>,

    // Vecteur pour stocker les fragments TCP reçus
    pub request_fragments: Arc<Mutex<HashMap<u16, Vec<Vec<u8>>>>>,

    // File des fragments TCP de réponse
    pub response_fragments: Arc<Mutex<HashMap<u16, Vec<String>>>>,

    // Resolver for forwarding DNS requests
    pub resolver: Arc<
        AsyncResolver<
            hickory_resolver::name_server::GenericConnector<
                hickory_resolver::name_server::TokioRuntimeProvider,
            >,
        >,
    >,
}

impl Handler {
    /// Create new handler from command-line options.
    pub fn from_options(_options: &Options) -> Self {
        let domain = &_options.domain;

        // Create a resolver configuration pointing to 9.9.9.9
        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(hickory_resolver::config::NameServerConfig::new(
            std::net::SocketAddr::from_str("9.9.9.9:53").unwrap(),
            hickory_resolver::config::Protocol::Udp,
        ));
        let resolver_opts = ResolverOpts::default();

        // Create an async resolver
        let resolver = AsyncResolver::tokio(resolver_config, resolver_opts);

        Handler {
            // Nom de domaine
            root_zone: LowerName::from(Name::from_str(domain).unwrap()),
            // Route de test pour le client
            test_zone: LowerName::from(
                Name::from_str(format!("test.{}", domain).as_str()).unwrap(),
            ),

            // Initialisation de la hashmap pour les sockets
            sockets: Arc::new(Mutex::new(HashMap::new())),

            // Initialisation de la hashmap pour les fragments
            request_fragments: Arc::new(Mutex::new(HashMap::new())),

            // Initialisation de la hashmap pour les fragments de réponse
            response_fragments: Arc::new(Mutex::new(HashMap::new())),

            // DNS resolver
            resolver: Arc::new(resolver),
        }
    }
    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> Result<ResponseInfo, Error> {
        // make sure the request is a query
        if request.op_code() != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code()));
        }

        // make sure the message type is a query
        if request.message_type() != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type()));
        }

        // Forward DNS request to 9.9.9.9 resolver
        async fn forward_dns_request<'a, R: ResponseHandler>(
            handler: &'a Handler,
            request: &'a Request,
            mut responder: R,
            name: LowerName,
        ) -> Result<ResponseInfo, Error> {
            // Attempt to resolve the name using the resolver
            let response_records = handler
                .resolver
                .lookup(name.to_string(), request.query().query_type())
                .await
                .map_err(|e| {
                    eprintln!("DNS resolution error: {}", e);
                    e
                })?;

            // Create a response builder from the original request
            let builder = MessageResponseBuilder::from_message_request(request);

            // Prepare the response header
            let mut header = Header::response_from_request(request.header());
            header.set_authoritative(false);

            // Convert resolver records to server records
            let records: Vec<Record> = response_records
                .into_iter()
                .map(|record| Record::from_rdata(request.query().name().into(), 300, record))
                .collect();

            // Build and send the response
            let response = builder.build(header, records.iter(), &[], &[], &[]);
            Ok(responder.send_response(response).await?)
        }

        match request.query().name() {
            name if self.test_zone.zone_of(name) => {
                self.do_handle_request_test(request, response).await
            }
            name if name.to_string().starts_with("data.") => {
                self.do_handle_request_data(request, response).await
            }
            name if name.to_string().starts_with("create.") => {
                self.do_handle_request_create(request, response).await
            }
            name if name.to_string().starts_with("response.") => {
                todo!("Implémenter le handle pour les réponses")
            }
            name => {
                // If the domain is not in our custom zones, forward to 9.9.9.9
                forward_dns_request(self, request, response, name.clone()).await
            }
        }
    }

    /// Handle requests for *.hello.{domain}.
    async fn do_handle_request_test<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        // Crée un constructeur de réponse à partir de la requête
        let builder = MessageResponseBuilder::from_message_request(request);

        // Prépare l'en-tête de la réponse
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        // Crée l'enregistrement TXT avec la chaîne construite
        let rdata = RData::TXT(TXT::new(vec![String::from("OK")]));

        // Crée la liste des enregistrements avec une TTL de 60 secondes
        let records = vec![Record::from_rdata(request.query().name().into(), 0, rdata)];

        // Construit la réponse finale
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        println!("==================== INFO =================");
        println!("Number of sockets: {}", self.sockets.lock().unwrap().len());
        println!(
            "Sockets uids: {:?}",
            self.sockets.lock().unwrap().keys().collect::<Vec<&u16>>()
        );
        println!(
            "Request fragments for all uids: {:?}",
            self.request_fragments.lock().unwrap()
        );
        println!(
            "Response fragments for all uids: {:?}",
            self.response_fragments.lock().unwrap()
        );
        // Envoie la réponse
        Ok(responder.send_response(response).await?)
    }
    async fn do_handle_request_create<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        // Crée un constructeur de réponse à partir de la requête
        let builder = MessageResponseBuilder::from_message_request(request);

        // Prépare l'en-tête de la réponse
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        // Requête de forme
        // CREATE.[HOST_B32].[PORT].[DOMAIN]
        // HOST_B32 : base32 encoded host IPv4 address

        let mut message = String::from("-1");

        // Récupère les parties de la requête
        let parts: Vec<String> = request
            .query()
            .name()
            .to_string()
            .split('.')
            .map(|s| s.to_string())
            .collect();

        let _host = match String::from_utf8(decode_base32(vec![parts[1].clone()])[0].clone()) {
            Ok(h) => h,
            Err(_) => String::new(),
        };

        let port: u16 = match parts[2].parse() {
            Ok(p) => p,
            Err(_) => 0,
        };

        if !_host.is_empty() && port != 0 {
            println!("INFO : Trying to open a socket to {}:{}", _host, port);

            // Trying to open a socket
            if let Ok(socket) = TcpStream::connect(format!("{}:{}", _host, port)) {
                // Génère un UID
                let session_id = utils::generate_u16_uuid();

                // Stocke le socket dans la hashmap
                self.sockets.lock().unwrap().insert(session_id, socket);

                message = session_id.to_string();

                println!("INFO : Socket created for session ID : {}", session_id);
            } else {
                println!("ERROR: Socket creation to {}:{} failed", _host, port);
            }
        }

        // Crée l'enregistrement TXT avec la chaîne construite
        let rdata = RData::TXT(TXT::new(vec![message.to_string()]));

        // Crée la liste des enregistrements avec une TTL de 60 secondes
        let records = vec![Record::from_rdata(request.query().name().into(), 0, rdata)];

        // Construit la réponse finale
        let response = builder.build(header, records.iter(), &[], &[], &[]);

        // Envoie la réponse
        Ok(responder.send_response(response).await?)
    }

    /// Handle requests for *.hello.{domain}.
    async fn do_handle_request_data<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        // Crée un constructeur de réponse à partir de la requête
        let builder = MessageResponseBuilder::from_message_request(request);

        // Prépare l'en-tête de la réponse
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        let mut message = String::from("OK");

        // DATA.[DATA_B32].[SEQ].[MAXSEQ].[UID].[DOMAIN]
        println!(
            "Data request received: {}",
            request.query().name().to_string()
        );
        let parts: Vec<String> = request
            .query()
            .name()
            .to_string()
            .split('.')
            .map(|s| s.to_string())
            .collect();

        let uid: u16 = match parts[4].parse() {
            Ok(p) => {
                if !self.sockets.lock().unwrap().contains_key(&p) {
                    eprintln!("Uid does not exist in sockets");
                    message = String::from("Uid does not exist in sockets");
                }
                p
            }
            Err(_) => {
                eprintln!("Invalid uid received");
                message = String::from("Invalid uid");
                0
            }
        };

        let _data = decode_base32(vec![parts[1].clone()])[0].clone();

        let maxseq: u16 = match parts[3].parse() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Invalid max sequence number received");
                message = String::from("Invalid max sequence number");
                0
            }
        };

        let seq: u16 = match parts[2].parse() {
            Ok(p) => {
                if p >= maxseq {
                    message = String::from("Sequence number greater than or equal to max sequence");
                }
                p
            }
            Err(_) => {
                eprintln!("Invalid sequence number received");
                message = String::from("Invalid sequence number");
                0
            }
        };

        if message == "OK" {
            // Préparation de la structure de donnée dans le cas où ce n'est pas encore fait
            if !self.request_fragments.lock().unwrap().contains_key(&uid)
                || self
                    .request_fragments
                    .lock()
                    .unwrap()
                    .get(&uid)
                    .unwrap()
                    .is_empty()
            {
                // Instantialisation de seqmax vecteurs
                let mut fragments = Vec::with_capacity(usize::from(maxseq));
                fragments.resize(usize::from(maxseq), Vec::new());
                self.request_fragments
                    .lock()
                    .unwrap()
                    .insert(uid, fragments);
            }

            // Ajout des données dans la bonne case
            self.request_fragments
                .lock()
                .unwrap()
                .get_mut(&uid)
                .unwrap()[usize::from(seq)] = _data;

            // Check il all usize vec are not empty
            let mut request_complete = true;
            for fragment in self.request_fragments.lock().unwrap().get(&uid).unwrap() {
                if fragment.is_empty() {
                    request_complete = false;
                    break;
                }
            }

            if request_complete {
                match self.send_data_to_remote_server(uid).await {
                    Ok(_) => (),
                    Err(_) => eprintln!("Failed to send data to remote server"),
                }
            }
        }

        // Crée l'enregistrement TXT avec la chaîne construite
        let rdata = RData::TXT(TXT::new(vec![message]));

        // Crée la liste des enregistrements avec une TTL de 60 secondes
        let records = vec![Record::from_rdata(request.query().name().into(), 0, rdata)];

        // Construit la réponse finale
        let response = builder.build(header, records.iter(), &[], &[], &[]);

        // Envoie la réponse
        Ok(responder.send_response(response).await?)
    }

    async fn send_data_to_remote_server(&self, session_id: u16) -> Result<(), ()> {
        println!("==================== INFO =================");
        println!("Number of sockets: {}", self.sockets.lock().unwrap().len());
        println!(
            "Sockets uids: {:?}",
            self.sockets.lock().unwrap().keys().collect::<Vec<&u16>>()
        );
        println!(
            "Request fragments for all uids: {:?}",
            self.request_fragments.lock().unwrap()
        );
        println!(
            "Response fragments for all uids: {:?}",
            self.response_fragments.lock().unwrap()
        );
        println!("Trying to send data to remote server...");
        println!("Acquiring socket lock...");
        let sockets = self.sockets.lock().unwrap();
        println!("Socket lock acquired");

        if !sockets.contains_key(&session_id) {
            eprintln!("Socket not found for session id {}", session_id);
            return Err(());
        }
        println!("Found socket for session ID {}", session_id);

        let socket = sockets.get(&session_id).unwrap();
        println!("Retrieved socket from hashmap");

        println!("Socket is alive");

        println!("Retrieving data fragments...");
        let data = {
            let data_container = self.request_fragments.lock().unwrap();
            let fragment_vec = data_container.get(&session_id).unwrap();
            fragment_vec.iter().flatten().cloned().collect::<Vec<u8>>()
        };
        println!(
            "Data fragments retrieved and assembled, size: {} bytes",
            data.len()
        );

        println!("Cloning socket for write operation...");
        let mut socket = socket.try_clone().unwrap();
        if let Err(e) = socket.write_all(&data) {
            eprintln!("Failed to write to socket: {}", e);
            return Err(());
        }
        println!("Successfully wrote {} bytes to socket", data.len());

        println!("Starting to read response...");
        let mut response = Vec::new();
        let mut buffer = vec![0u8; 1024];
        let mut read_attempt = 0;
        loop {
            match socket.read(&mut buffer) {
                Ok(n) if n == 0 => {
                    println!("Finished reading response");
                    if !response.is_empty() {
                        break;
                    }
                    read_attempt += 1;
                    if read_attempt > 3 {
                        println!("No more data after 3 attempts");
                        break;
                    }
                }
                Ok(n) => {
                    println!("Read {} bytes from socket", n);
                    response.extend_from_slice(&buffer[..n]);
                    break;
                }
                Err(e) => {
                    eprintln!("Failed to read from socket: {}", e);
                    return Err(());
                }
            }
        }
        println!("Total response size: {} bytes", response.len());

        println!("Base32 encoding response...");
        let mut response_splitted = Vec::new();
        let encoded = base32::encode(Alphabet::Rfc4648 { padding: false }, &response);
        println!("Response encoded, splitting into chunks...");

        for (i, chunk) in encoded.as_bytes().chunks(254).enumerate() {
            let chunk_str = String::from_utf8(chunk.to_vec()).unwrap();
            println!("Created chunk {} of length {}", i, chunk_str.len());
            response_splitted.push(chunk_str);
        }
        println!("Created {} response chunks", response_splitted.len());

        println!("Storing response fragments...");
        self.response_fragments
            .lock()
            .unwrap()
            .insert(session_id, response_splitted);
        println!("Response fragments stored successfully");

        Ok(())
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        // try to handle request
        match self.do_handle_request(request, response).await {
            Ok(info) => info,
            Err(error) => {
                eprintln!("Error in RequestHandler: {error}");
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}
