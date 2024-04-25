use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;
use actix_web::HttpRequest;
use log::{error, info, warn};
use content_queue::content_queue::ContentQueue;

use content_queue::message::{
    DocumentActionType,
    DocumentMessage,
    DocumentMessageType,
    DocumentSignature,
};
use content_queue::sqs_content_queue::SQSContentQueue;

use fedineko_http_client::GenericClient;
use pinnifed::HttpMethod;
use lazy_activitypub::activity::Activity;
use lazy_activitypub::entity::{EntityType, is_supported_content_type};
use lazy_activitypub::object::{ObjectTrait};
use puprik_signature::request_verifier::SignatureVerifier;
use crate::public_key_cache::{KeyStatus, PublicKeyCache};

/// Queues used by octofedi sink.
pub(crate) struct SinkQueues {
    /// Queue for content to process and either index or drop.
    pub content_queue: SQSContentQueue,

    /// Queue for requests, e.g. opt-out or search requests.
    pub requests_queue: SQSContentQueue,
}

/// Wrapper for Activity received by octofedi.
struct SinkItem {
    /// Activity object itself.
    pub activity: Activity,

    /// Request headers used to e.g. validate signature.
    pub headers: HashMap<String, String>,

    /// Address of peer who sent this activity.
    /// It is as unreliable as it could be as could be inferred
    /// from request headers.
    /// Therefore, MUST NOT be trusted.
    pub peer: String,

    /// Addressee of the activity.
    pub target: url::Url,
}

/// Helper structure to accumulate messages to send into queues.
/// It is split into multiple maps to reduce queue API usage
/// and associated costs. E.g. if content is crated and then
/// immediately updated then there is no need to keep create
/// activity as time of processing it will be duplicated work,
/// unnecessary load for Fedineko and Fediverse service instance.
struct Messages {
    /// Keeps information about Create activities.
    pub create_activities: HashMap<url::Url, DocumentMessage>,

    /// Keeps information about Update activities.
    pub update_activities: HashMap<url::Url, DocumentMessage>,

    /// Keeps information about Delete activities.
    pub delete_activities: HashMap<url::Url, DocumentMessage>,

    /// Keeps information about Announce activities.
    /// From user point of view it is either boosts, or re-notes,
    /// or something similar.
    pub announce_activities: HashMap<url::Url, DocumentMessage>,

    /// Keeps information about subscribe activities, including
    /// Accept, Follow and Reject.
    pub subscribe_activities: HashMap<url::Url, DocumentMessage>,
}

impl Messages {
    /// This method checks if there is any activity to process at all.
    pub fn is_empty(&self) -> bool {
        self.announce_activities.is_empty() &&
            self.delete_activities.is_empty() &&
            self.create_activities.is_empty() &&
            self.update_activities.is_empty() &&
            self.subscribe_activities.is_empty()
    }

    /// This method consumes and flattens all internal maps into single vector.
    pub fn into_vec(self) -> Vec<DocumentMessage> {
        self.create_activities.into_values()
            .chain(self.announce_activities.into_values())
            .chain(self.update_activities.into_values())
            .chain(self.delete_activities.into_values())
            .chain(self.subscribe_activities.into_values())
            .collect()
    }
}

/// Sink object accumulates activities and knows when to process those.
pub(crate) struct Sink {
    /// Activities to process.
    items: Mutex<RefCell<Vec<SinkItem>>>,

    /// Public keys cache used to validate activities signatures.
    public_cache_key: PublicKeyCache,

    /// Actual verifier for request signatures.
    signature_verifier: SignatureVerifier,

    /// This server URL, such as `https://fedineko.org`.
    /// It is used to e.g. understand if activity is addressed to Fedineko.
    server_url: url::Url,
}

impl Sink {
    /// Constructs new instance of [Sink] with `server_url` as address
    /// of Fedineko instance.
    pub fn new(server_url: url::Url) -> Self {
        Self {
            items: Mutex::new(RefCell::new(vec![])),
            public_cache_key: PublicKeyCache::new(2048),
            signature_verifier: SignatureVerifier::new(),
            server_url,
        }
    }

    /// This method stores `activity` as in internal collection of items
    /// to process. `request` is consumed to extract headers required
    /// for signature validation.
    pub fn push(&self, activity: Activity, request: HttpRequest) {
        let headers: HashMap<_, _> = request.headers()
            .iter()
            .filter_map(|(k, v)| {
                match v.to_str() {
                    Ok(val) => Some((k.to_string(), val.to_string())),

                    Err(err) => {
                        warn!("Failed to convert header value {v:?}: {err:?}");
                        None
                    }
                }
            })
            .collect();

        let peer = request.connection_info()
            .realip_remote_addr()
            .unwrap_or("")
            .to_string();

        let target = self.server_url.join(request.path())
            .unwrap();

        self.items.lock()
            .unwrap()
            .borrow_mut()
            .push(
                SinkItem {
                    activity,
                    headers,
                    peer,
                    target,
                }
            )
    }

    /// This method verifies signature passed in headers for sink `item`.
    /// If needed, requests remote public key using given `client`.
    /// Returns information about signature state, with
    /// [DocumentSignature::Valid] being the only relatively safe option
    /// to indicate that document could be processed.
    async fn verify_headers(
        &self,
        item: &SinkItem,
        client: &GenericClient,
    ) -> DocumentSignature {
        let sliced_headers = item.headers.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let key_details = match self.signature_verifier.get_key_details(
            &sliced_headers
        ) {
            None => {
                warn!(
                    "Item {} from peer {} does not have public key details",
                    item.activity.activity_id(),
                    item.peer
                );

                return DocumentSignature::Unknown;
            }

            Some(value) => value,
        };

        let owner = match url::Url::parse(key_details.id()) {
            Ok(url) => url,

            Err(err) => {
                error!(
                    "Failed to parse {} as a valid URL: {err:?}",
                    key_details.id()
                );

                return DocumentSignature::Unknown;
            }
        };

        let key_status = self.public_cache_key.get_public_key(
            key_details.id(), key_details.alg(), &owner, client,
        ).await;

        match key_status {
            KeyStatus::Key(key) => {
                match self.signature_verifier.verify_headers(
                    sliced_headers, &item.target, HttpMethod::Post, &key,
                ) {
                    true => DocumentSignature::Valid(key.key_id().to_string()),

                    false => {
                        warn!(
                            "Invalid signature. key_id: {} ({}), \
                            owner: {owner}, headers: {:?}",
                            key_details.id(),
                            key.key_id(),
                            item.headers
                        );

                        DocumentSignature::Invalid
                    }
                }
            }

            KeyStatus::NoKey => DocumentSignature::Unknown,
            KeyStatus::IgnoreContent => DocumentSignature::DropContent
        }
    }

    /// This method processes sink `item` and stores it into map of document
    /// messages. `object_id` represents activity identifier, `client` is
    /// used to acquire remote public key if is not available in local cache.
    /// `activities` map is passed through, it is updated with document message
    /// if signature is valid and no any error happen during handling.
    async fn push_activity(
        &self,
        object_id: url::Url,
        item: SinkItem,
        client: &GenericClient,
        mut activities: HashMap<url::Url, DocumentMessage>,
    ) -> HashMap<url::Url, DocumentMessage> {
        let signature_status = self.verify_headers(&item, client).await;
        let id = object_id.to_string();

        match signature_status {
            DocumentSignature::Valid(_) => {
                /* fall through */
            }

            DocumentSignature::Invalid |
            DocumentSignature::Unknown => {
                warn!(
                    "Dropping {id} as signature validation failed: \
                    {signature_status:?}"
                );

                return activities;
            }

            DocumentSignature::DropContent => {
                warn!(
                    "Dropping {id} as prescribed by signature validation logic"
                );

                return activities;
            }
        }

        // Signature is valid, so activity needs to be converted into
        // message to send to oceanhorse.
        let activity_type = item.activity.entity_type();

        let (action, message_type, content) = match activity_type {
            EntityType::Announce => (
                DocumentActionType::Announce,
                DocumentMessageType::ContentId,
                id.clone()
            ),

            EntityType::Create => (
                DocumentActionType::Create,
                DocumentMessageType::Content,
                serde_json::to_string(&item.activity).unwrap()
            ),

            EntityType::Delete => (
                DocumentActionType::Delete,
                DocumentMessageType::Content,
                serde_json::to_string(&item.activity).unwrap()
            ),

            EntityType::Update => (
                DocumentActionType::Update,
                DocumentMessageType::Content,
                serde_json::to_string(&item.activity).unwrap()
            ),

            EntityType::Follow |
            EntityType::Accept |
            EntityType::Reject => (
                DocumentActionType::Subscribe,
                DocumentMessageType::Content,
                serde_json::to_string(&item.activity).unwrap()
            ),

            _ => {
                warn!(
                    "{object_id}: Unsupported activity type: {:?}",
                    item.activity.entity_type()
                );

                return activities;
            }
        };

        let targets_fedineko = if matches!(
            activity_type,
            EntityType::Follow | EntityType::Accept | EntityType::Reject
        ) {
            true
        } else {
            item.activity.to_field_matches(self.server_url.as_str())
        };

        let message = DocumentMessage {
            content_id: id,
            action,
            message_type,
            content,
            source: Some(item.peer),
            signature_status,
            targets_fedineko,
        };

        activities.insert(object_id, message);

        activities
    }

    /// This method process accumulated `sink_items` and splits into different
    /// buckets of activities. `client` is under the hood to retrieve public
    /// key to verify signatures.
    async fn prepare_messages(
        &self,
        sink_items: Vec<SinkItem>,
        client: &GenericClient,
    ) -> Messages {
        let mut create_activities: HashMap<_, _> = HashMap::new();
        let mut update_activities: HashMap<_, _> = HashMap::new();
        let mut delete_activities: HashMap<_, _> = HashMap::new();
        let mut announce_activities: HashMap<_, _> = HashMap::new();
        let mut subscribe_activities: HashMap<_, _> = HashMap::new();

        for item in sink_items.into_iter() {
            let object_id = match item.activity.inner_object_id() {
                None => continue,
                Some(url) => url,
            };

            if delete_activities.contains_key(&object_id) {
                info!("{object_id}: Already in batch to delete");
                continue;
            }

            let object_type = item.activity.inner_object_type();

            match item.activity.entity_type() {
                EntityType::Announce => {
                    // TODO: announcements could have fragments like #undo or
                    //       #updates, so needs to be either ignored or
                    //       verified against existing entry, ignoring fragment.
                    if create_activities.contains_key(&object_id) ||
                        update_activities.contains_key(&object_id) ||
                        announce_activities.contains_key(&object_id) {
                        info!("{object_id}: Already in batch to process");
                        continue;
                    }

                    announce_activities = self.push_activity(
                        object_id,
                        item,
                        client,
                        announce_activities,
                    ).await;
                }

                EntityType::Create => {
                    if !is_supported_content_type(object_type) {
                        warn!(
                            "{object_id}: Ignored Create activity \
                            for unsupported type {object_type}",
                        );

                        continue;
                    }

                    if create_activities.contains_key(&object_id) ||
                        update_activities.contains_key(&object_id) {
                        info!("{object_id}: Already in Create batch");
                        continue;
                    }

                    // Create allows to avoid requesting content,
                    // meaning less traffic for Fedineko and less load
                    // for Fediverse server instance.
                    announce_activities.remove(&object_id);

                    create_activities = self.push_activity(
                        object_id,
                        item,
                        client,
                        create_activities,
                    ).await;
                }

                EntityType::Delete => {
                    if create_activities.contains_key(&object_id) {
                        info!(
                            "{object_id}: Removing from create batch \
                            as it is going to be deleted"
                        );

                        create_activities.remove(&object_id);
                    }

                    if update_activities.contains_key(&object_id) {
                        info!(
                            "{object_id}: Removing from update batch \
                            as it is going to be deleted"
                        );

                        update_activities.remove(&object_id);
                    }

                    if announce_activities.contains_key(&object_id) {
                        info!(
                            "{object_id}: Removing from announce batch \
                            as it is going to be deleted"
                        );

                        announce_activities.remove(&object_id);
                    }

                    delete_activities = self.push_activity(
                        object_id,
                        item,
                        client,
                        delete_activities,
                    ).await;
                }

                EntityType::Update => {
                    if !is_supported_content_type(object_type) {
                        warn!(
                            "{object_id}: Ignored as it is Update activity \
                            for unsupported content type {object_type}"
                        );

                        continue;
                    }

                    if update_activities.contains_key(&object_id) {
                        info!(
                            "{object_id}: Already in Update batch, \
                            replacing with the new one"
                        );

                        update_activities.remove(&object_id);
                    }

                    if create_activities.contains_key(&object_id) {
                        info!(
                            "{object_id}: Moving from Create to Update batch"
                        );

                        create_activities.remove(&object_id);
                    }

                    if announce_activities.contains_key(&object_id) {
                        info!(
                            "{object_id}: Moving from Announce to Update batch"
                        );

                        announce_activities.remove(&object_id);
                    }

                    update_activities = self.push_activity(
                        object_id,
                        item,
                        client,
                        update_activities,
                    ).await;
                }

                EntityType::Follow |
                EntityType::Accept |
                EntityType::Reject => {
                    if subscribe_activities.contains_key(&object_id) {
                        info!(
                            "{object_id}: Already in Subscribe batch, \
                            replacing with the new one"
                        );

                        subscribe_activities.remove(&object_id);
                    }

                    subscribe_activities = self.push_activity(
                        object_id,
                        item,
                        client,
                        subscribe_activities,
                    ).await;
                }
                _ => {}
            }
        }

        Messages {
            create_activities,
            update_activities,
            delete_activities,
            announce_activities,
            subscribe_activities,
        }
    }

    /// This is main processing method.
    ///
    /// - `sink_queues` is a couple of queues to send document messages to.
    /// - `client` is HTTP client to use for remote content fetching.
    pub async fn process(
        &self,
        sink_queues: &SinkQueues,
        client: &GenericClient,
    ) {
        let items: Vec<_> = {
            self.items.lock()
                .unwrap()
                .take()
        };

        if items.is_empty() {
            info!("No activities to process");
            return;
        }

        let messages = self.prepare_messages(items, client).await;

        if messages.is_empty() {
            info!("No activities to push");
            return;
        }

        let document_messages = messages.into_vec();
        let mut content_messages = vec![];
        let mut fedineko_targeted_messages = vec![];

        document_messages.into_iter()
            .for_each(|msg| {
                if msg.targets_fedineko {
                    fedineko_targeted_messages.push(msg);
                } else {
                    content_messages.push(msg);
                }
            });

        if let Err(err) = sink_queues.content_queue.push_messages(
            content_messages
        ).await {
            // fail but continue, that batch is lost.
            error!("Failed to send messages to content queue: {err:?}");
        }

        if !fedineko_targeted_messages.is_empty() {
            info!(
                "Messages targeting Fedineko: {fedineko_targeted_messages:?}"
            );
        }

        if let Err(err) = sink_queues.requests_queue.push_messages(
            fedineko_targeted_messages
        ).await {
            // TODO: Need to handle it better. Losing this messages
            //       is more impactful than messages above.
            error!("Failed to send messages to content queue: {err:?}")
        }
    }

    /// Returns number of items accumulated so far.
    pub fn items(&self) -> usize {
        self.items.lock()
            .unwrap()
            .borrow()
            .len()
    }
}
