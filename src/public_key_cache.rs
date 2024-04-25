use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};
use actix_web::http::StatusCode;
use actix_web::web::{Buf, Bytes};
use log::{info, warn};
use lru::LruCache;
use fedineko_http_client::{ClientError, GenericClient};
use lazy_activitypub::actor::Actor;
use puprik::public_key::PublicKey;

/// Information about cached key.
#[derive(Clone)]
pub(crate) enum KeyStatus {
    /// Key data itself.
    Key(Arc<PublicKey>),

    /// No key in cache, e.g. instance hosting key is not available.
    NoKey,

    /// Status to indicate that content referencing this key should be dropped.
    /// This could happen if key reference is malformed, not available even
    /// though referenced and actor information is accessible, not loadable, etc.
    IgnoreContent,
}

/// This is a basic public key cache implementation.
pub(crate) struct PublicKeyCache {
    /// Cache of valid keys.
    key_cache: RwLock<LruCache<String, Arc<PublicKey>>>,

    /// Cache for invalid keys.
    negative_hits: RwLock<LruCache<String, KeyStatus>>,
}

impl PublicKeyCache {
    /// This method created new instance of [PublicKeyCache] capable
    /// of storing `cache_size` items in both internal caches.
    pub fn new(cache_size: usize) -> Self {
        Self {
            key_cache: RwLock::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap()
            )),

            negative_hits: RwLock::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap()
            )),
        }
    }

    /// This helper method extracts information about key from Actor object
    /// passed in serialized `data`. `key_id` identifies key to look for,
    /// `key_alg` could be used as a hint for algorithm of key.
    fn extract_public_key(
        &self,
        key_id: &str,
        key_alg: Option<&str>,
        data: Bytes,
    ) -> KeyStatus {
        let actor: Actor = match serde_json::from_reader(data.reader()) {
            Ok(actor) => actor,

            Err(err) => {
                warn!("Failed to parse actor for key {}: {err:?}", key_id);
                return KeyStatus::IgnoreContent;
            }
        };

        if actor.public_key.is_none() {
            warn!("Actor for key {} have no key data", key_id);
            return KeyStatus::IgnoreContent;
        }

        let key_reference = actor.public_key.unwrap();

        key_reference.get_by_id(key_id)
            .or_else(|| key_reference.get_any())
            .cloned()
            .map(|public_key| {
                if let Some(crypto_key) = PublicKey::from_pem_text(
                    key_id, &public_key.public_key_pem, key_alg,
                ) {
                    info!("Putting {key_id} to cache");

                    let key = Arc::new(crypto_key);

                    self.key_cache.write()
                        .unwrap()
                        .put(key_id.to_string(), key.clone());

                    KeyStatus::Key(key)
                } else {
                    KeyStatus::IgnoreContent
                }
            }).unwrap_or(KeyStatus::IgnoreContent)
    }

    /// Helper method to handle remote key `key_id` loading error `err`.
    fn handle_client_error(
        &self,
        key_id: &str,
        err: ClientError,
    ) -> KeyStatus {
        warn!("Failed to get key {key_id}: {err:?}");

        let key_status = if let ClientError::UnexpectedStatusCode(
            status_code
        ) = err {
            match status_code {
                StatusCode::NOT_FOUND |
                StatusCode::GONE => KeyStatus::IgnoreContent,

                _ => KeyStatus::NoKey,
            }
        } else {
            KeyStatus::NoKey
        };

        self.negative_hits.write()
            .unwrap()
            .put(key_id.to_string(), key_status.clone());

        key_status
    }

    /// This method loads key either from cache or from remote location.
    ///
    /// - `key_id` is identifier of the key.
    /// - `key_alg` is algorithm hint, if known.
    /// - `owner` is actor, owner of the key.
    /// - `client` is HTTP client to acquire remote key.
    pub(crate) async fn get_public_key(
        &self,
        key_id: &str,
        key_alg: Option<&str>,
        owner: &url::Url,
        client: &GenericClient,
    ) -> KeyStatus {
        if let Some(public_key) = self.key_cache.write()
            .unwrap()
            .get(key_id)
        {
            return KeyStatus::Key(public_key.clone());
        }

        if let Some(status) = self.negative_hits.write()
            .unwrap()
            .get(key_id)
        {
            info!("Key {key_id} is in negative hits cache");
            return status.clone();
        }

        info!("Requesting remote key: {key_id}");

        match client.get_bytes(owner, None).await
        {
            Ok(data) => {
                let key_status = self.extract_public_key(
                    key_id,
                    key_alg,
                    data,
                );

                if matches!(
                    key_status,
                    KeyStatus::NoKey | KeyStatus::IgnoreContent
                ) {
                    self.negative_hits.write()
                        .unwrap()
                        .put(key_id.to_string(), key_status.clone());
                }

                key_status
            }

            Err(err) => {
                self.handle_client_error(key_id, err)
            }
        }
    }
}