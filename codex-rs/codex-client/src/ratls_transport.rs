//! RA-TLS transport implementation for attested connections to TEEs.
//!
//! This module provides an HTTP transport that establishes TLS connections
//! with Remote Attestation verification, ensuring the server is running
//! in a trusted execution environment (TEE).

use crate::error::TransportError;
use crate::request::Request;
use crate::request::Response;
use crate::transport::{HttpTransport, StreamResponse};
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use http::{HeaderMap, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use ratls_core::{ratls_connect, AttestationResult, Policy};
use tokio::net::TcpStream;

/// Transport that establishes RA-TLS connections with attestation verification.
#[derive(Clone)]
pub struct RatlsTransport {
    policy: Policy,
}

impl RatlsTransport {
    /// Create a new RA-TLS transport with the given attestation policy.
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// Extract host, port, and path from URL.
    fn parse_url(url: &str) -> Result<(String, u16, String), TransportError> {
        let url =
            url::Url::parse(url).map_err(|e| TransportError::Build(format!("invalid URL: {e}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| TransportError::Build("missing host".into()))?
            .to_string();
        let port = url.port().unwrap_or(443);
        let path = url.path().to_string();
        let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
        Ok((host, port, format!("{path}{query}")))
    }

    /// Establish a new attested TLS connection.
    async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> Result<
        (
            http1::SendRequest<Full<Bytes>>,
            AttestationResult,
            tokio::task::JoinHandle<()>,
        ),
        TransportError,
    > {
        let addr = format!("{host}:{port}");
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| TransportError::Network(format!("TCP connect failed: {e}")))?;

        let (tls_stream, attestation) = ratls_connect(
            tcp,
            host,
            self.policy.clone(),
            Some(vec!["http/1.1".into()]),
        )
        .await
        .map_err(|e| TransportError::Network(format!("RA-TLS failed: {e}")))?;

        if !attestation.trusted {
            return Err(TransportError::Network(
                "Attestation verification failed: TEE not trusted".into(),
            ));
        }

        tracing::info!(
            tee_type = ?attestation.tee_type,
            tcb_status = %attestation.tcb_status,
            measurement = ?attestation.measurement,
            "RA-TLS connection established with trusted TEE"
        );

        // Wrap the TLS stream for hyper
        let io = TokioIo::new(tls_stream);

        // Create HTTP/1.1 connection
        let (sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| TransportError::Network(format!("HTTP handshake failed: {e}")))?;

        // Spawn the connection driver
        let handle = tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::warn!("HTTP connection error: {e}");
            }
        });

        Ok((sender, attestation, handle))
    }

    /// Get or create a connection to the specified host.
    async fn get_connection(
        &self,
        host: &str,
        port: u16,
    ) -> Result<(http1::SendRequest<Full<Bytes>>, AttestationResult), TransportError> {
        // For now, create a new connection for each request.
        // Future optimization: implement connection pooling with attestation caching.
        let (sender, attestation, _handle) = self.connect(host, port).await?;
        Ok((sender, attestation))
    }

    /// Build an HTTP request from our Request type.
    fn build_http_request(
        &self,
        method: &http::Method,
        host: &str,
        path: &str,
        headers: &HeaderMap,
        body: Option<&serde_json::Value>,
    ) -> Result<hyper::Request<Full<Bytes>>, TransportError> {
        let uri = path;

        let body_bytes = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|e| TransportError::Build(format!("JSON serialization failed: {e}")))?
            .map(Bytes::from)
            .unwrap_or_default();

        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .header("Host", host);

        for (name, value) in headers.iter() {
            builder = builder.header(name, value);
        }

        if !body_bytes.is_empty() {
            builder = builder.header("Content-Length", body_bytes.len());
            if !headers.contains_key("Content-Type") {
                builder = builder.header("Content-Type", "application/json");
            }
        }

        builder
            .body(Full::new(body_bytes))
            .map_err(|e| TransportError::Build(format!("Failed to build request: {e}")))
    }

    /// Convert hyper response to our Response type.
    async fn response_to_bytes(
        status: StatusCode,
        headers: HeaderMap,
        body: Incoming,
    ) -> Result<Response, TransportError> {
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| TransportError::Network(format!("Failed to read response body: {e}")))?
            .to_bytes();

        if !status.is_success() {
            let body_str = String::from_utf8(body_bytes.to_vec()).ok();
            return Err(TransportError::Http {
                status,
                headers: Some(headers),
                body: body_str,
            });
        }

        Ok(Response {
            status,
            headers,
            body: body_bytes,
        })
    }
}

#[async_trait]
impl HttpTransport for RatlsTransport {
    async fn execute(&self, req: Request) -> Result<Response, TransportError> {
        let (host, port, path) = Self::parse_url(&req.url)?;
        let (mut sender, _attestation) = self.get_connection(&host, port).await?;

        let http_req = self.build_http_request(&req.method, &host, &path, &req.headers, req.body.as_ref())?;

        let response = sender
            .send_request(http_req)
            .await
            .map_err(|e| TransportError::Network(format!("Request failed: {e}")))?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body();

        Self::response_to_bytes(status, headers, body).await
    }

    async fn stream(&self, req: Request) -> Result<StreamResponse, TransportError> {
        let (host, port, path) = Self::parse_url(&req.url)?;
        let (mut sender, _attestation) = self.get_connection(&host, port).await?;

        let http_req = self.build_http_request(&req.method, &host, &path, &req.headers, req.body.as_ref())?;

        let response = sender
            .send_request(http_req)
            .await
            .map_err(|e| TransportError::Network(format!("Request failed: {e}")))?;

        let status = response.status();
        let headers = response.headers().clone();

        if !status.is_success() {
            let body = response.into_body();
            let body_bytes = body
                .collect()
                .await
                .map_err(|e| TransportError::Network(format!("Failed to read error body: {e}")))?
                .to_bytes();
            let body_str = String::from_utf8(body_bytes.to_vec()).ok();
            return Err(TransportError::Http {
                status,
                headers: Some(headers),
                body: body_str,
            });
        }

        // Convert the body into a stream
        let body = response.into_body();
        let stream = futures::stream::unfold(body, |mut body| async move {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        Some((Ok(data.clone()), body))
                    } else {
                        // Skip non-data frames (trailers)
                        Some((Ok(Bytes::new()), body))
                    }
                }
                Some(Err(e)) => Some((
                    Err(TransportError::Network(format!("Stream error: {e}"))),
                    body,
                )),
                None => None,
            }
        })
        .filter(|result| {
            // Filter out empty chunks
            futures::future::ready(!matches!(result, Ok(b) if b.is_empty()))
        });

        Ok(StreamResponse {
            status,
            headers,
            bytes: Box::pin(stream),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let (host, port, path) = RatlsTransport::parse_url("https://example.com/v1/chat").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/v1/chat");

        let (host, port, path) =
            RatlsTransport::parse_url("https://example.com:8443/api?foo=bar").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/api?foo=bar");
    }
}
