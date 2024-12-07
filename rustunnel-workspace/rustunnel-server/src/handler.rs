use rustunnel_lib::utils::{self, decode_base32};

use crate::options::Options;

use hickory_server::{
    authority::MessageResponseBuilder,
    proto::op::{Header, MessageType, OpCode, ResponseCode},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

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
    pub response_fragments: Arc<Mutex<HashMap<u16, String>>>,
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
            name => Err(Error::InvalidZone(name.clone())),
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
                todo!("Redirigé à la fonction de transfert")
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
