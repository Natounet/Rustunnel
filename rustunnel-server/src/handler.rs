use crate::{
    dns,
    options::{self, Options},
    utils::{self, decode_base32},
};

use hickory_server::{
    authority::MessageResponseBuilder,
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

use hickory_proto::rr::{rdata::TXT, LowerName, Name, RData, Record};

use std::{
    borrow::Borrow,
    net::IpAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

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
}

/// DNS Request Handler
#[derive(Clone, Debug)]
pub struct Handler {
    pub root_zone: LowerName,
    pub test_zone: LowerName,

    // Hashmap pour stocker les sockets ouverts
    pub sockets: Arc<Mutex<HashMap<u16, TcpStream>>>,

    // Vecteur pour stocker les fragments TCP reçus
    pub request_fragments: Arc<Mutex<HashMap<u16, Vec<u8>>>>,

    // File des fragments TCP de réponse
    pub response_fragments: Arc<Mutex<HashMap<u16, Vec<u8>>>>,
}

impl Handler {
    /// Create new handler from command-line options.
    pub fn from_options(_options: &Options) -> Self {
        let domain = &_options.domain;
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

        match request.query().name() {
            name if self.test_zone.zone_of(name) => {
                self.do_handle_request_hello(request, response).await
            }
            name if name.to_string().starts_with("data.") => {
                todo!("Implémenter le handle pour les données")
            }
            name if name.to_string().starts_with("create.") => {
                self.do_handle_request_create(request, response).await
            }
            name if name.to_string().starts_with("response.") => {
                todo!("Implémenter le handle pour les réponses")
            }
            name => Err(Error::InvalidZone(name.clone())),
        }
    }

    /// Handle requests for *.hello.{domain}.
    async fn do_handle_request_hello<R: ResponseHandler>(
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
        let rdata = RData::TXT(TXT::new(vec![String::from("Success !")]));

        // Crée la liste des enregistrements avec une TTL de 60 secondes
        let records = vec![Record::from_rdata(request.query().name().into(), 1, rdata)];

        // Construit la réponse finale
        let response = builder.build(header, records.iter(), &[], &[], &[]);

        // Envoie la réponse
        Ok(responder.send_response(response).await?)
    }
    // Handle requests for *.hello.{domain}.
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

        // Récupère les parties de la requête
        let parts: Vec<String> = request
            .query()
            .name()
            .to_string()
            .split('.')
            .map(|s| s.to_string())
            .collect();

        let _host: String =
            match String::from_utf8(decode_base32(vec![parts[1].clone()])[0].clone()) {
                Ok(h) => h,
                Err(_) => {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid host",
                    )))
                }
            };

        let port: u16 = match parts[2].parse() {
            Ok(p) => p,
            Err(_) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid port",
                )))
            }
        };

        // Trying to open a socket
        let socket = match TcpStream::connect(format!("{}:{}", _host, port)) {
            Ok(s) => s,
            Err(e) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e.to_string(),
                )))
            }
        };

        // Génère un UID
        let session_id = utils::generate_u16_uuid();

        // Stocke le socket dans la hashmap
        self.sockets.lock().unwrap().insert(session_id, socket);

        // Crée l'enregistrement TXT avec la chaîne construite
        let rdata = RData::TXT(TXT::new(vec![session_id.to_string()]));

        // Crée la liste des enregistrements avec une TTL de 60 secondes
        let records = vec![Record::from_rdata(request.query().name().into(), 1, rdata)];

        // Construit la réponse finale
        let response = builder.build(header, records.iter(), &[], &[], &[]);

        // Envoie la réponse
        Ok(responder.send_response(response).await?)
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
