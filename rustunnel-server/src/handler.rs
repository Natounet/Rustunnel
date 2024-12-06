use crate::{
    options::{self, Options},
    utils,
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

        // Génère un UID
        let session_id = utils::generate_u16_uuid();

        // Crée l'enregistrement TXT avec la chaîne construite
        let rdata = RData::TXT(TXT::new(vec![session_id.to_string()]));

        todo!("Implémenter l'ouverture de socket avant retour de l'ID");

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
