use lazy_activitypub::actor::{Actor, Endpoints, PublicKeyReference};
use lazy_activitypub::entity::{Entity, EntityType};
use lazy_activitypub::object::{Object, UrlReference};

use crate::APP_NAME;

/// Helper function to create Actor object exposed to Fediverse
/// as Fedineko user.
///
/// - `server_url` is this Fedineko instance address, base to
///               construct different URLs, e.g. about page.
/// - `actor` is URL of actor for which Actor object is created.
/// - `inbox` is Actor's inbox URL.
/// - `outbox` is Actor's outbpx URL, it is not really used and
///            exists just to make sure other services do not panic.
/// - `key_id` is actor's public key ID.
/// - `username` is preferred username for actor.
/// - `public_key_oneline` is PEM text of public key.
fn make_actor(
    server_url: &url::Url,
    actor: url::Url,
    inbox: url::Url,
    outbox: url::Url,
    key_id: url::Url,
    username: String,
    public_key_oneline: &str,
) -> Actor {
    let actor_key = lazy_activitypub::actor::PublicKey {
        id: key_id,
        owner: actor.clone(),
        public_key_pem: public_key_oneline.to_string(),
    };

    let about_url = server_url.join("/about").unwrap();
    let summary = format!("Fedineko indexing service ({about_url})");

    Actor {
        object_entity: Object {
            entity: Entity::new(EntityType::Application),
            id: actor.clone(),
            name: Some(username.clone()),
            url: Some(UrlReference::Url(inbox.clone())),
            to: None,
        },
        inbox,
        outbox: Some(outbox),
        // These two are defined but currently return 403.
        followers: Some(actor.join("/actor/followers").unwrap()),
        following: Some(actor.join("/actor/following").unwrap()),
        preferred_username: Some(username),
        endpoints: Some(
            Endpoints {
                shared_inbox: Some(server_url.join("/inbox").unwrap()),
            }
        ),
        name_map: None,
        summary: Some(summary),
        icon: None,
        public_key: Some(PublicKeyReference::Single(actor_key)),
        // Setting these do not harm, but not setting is fine as well.
        indexable: None,
        discoverable: None,
        searchable_by: None,
        tag: None,
        attachment: None,
    }
}

/// This function is wrapper around [make_actor()] to produce
/// server actor in a more convenient way.
/// - `server_url` is this Fedineko instance address, base to
///               construct different URLs, e.g. about page.
/// - `public_key_oneline` is PEM text of public key.
pub(crate) fn make_server_actor(
    server_url: &url::Url,
    public_key_oneline: &str,
) -> Actor {
    let actor = server_url.join("/actor").unwrap();
    let inbox = server_url.join("/actor/inbox").unwrap();
    let outbox = server_url.join("/actor/outbox").unwrap();
    let key_id = server_url.join("/actor#main-key").unwrap();

    make_actor(
        server_url,
        actor,
        inbox,
        outbox,
        key_id,
        APP_NAME.to_string(),
        public_key_oneline,
    )
}

/// This function is wrapper around [make_actor()] to produce
/// user actor in a more convenient way.
/// - `server_url` is this Fedineko instance address, base to
///               construct different URLs, e.g. about page.
/// - `username` is preferred username for actor.
/// - `public_key_oneline` is PEM text of public key.
pub(crate) fn make_user_actor(
    server_url: &url::Url,
    username: String,
    public_key_oneline: &str,
) -> Actor {
    let user_path = format!("/u/{username}");
    let user_inbox = format!("/u/{username}/inbox");
    let user_outbox = format!("/u/{username}/outbox");
    let key_path = format!("/u/{username}#main-key");

    let user_id = server_url.join(&user_path).unwrap();
    let inbox = server_url.join(&user_inbox).unwrap();
    let outbox = server_url.join(&user_outbox).unwrap();
    let key_id = server_url.join(&key_path).unwrap();

    make_actor(
        server_url,
        user_id,
        inbox,
        outbox,
        key_id,
        username,
        public_key_oneline,
    )
}