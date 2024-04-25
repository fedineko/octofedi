mod webfinger;
mod nodeinfo;
mod sink;
mod sink_task;
mod utils;
mod public_key_cache;

use std::env;
use std::sync::Arc;

use actix_web::{
    App,
    get,
    HttpRequest,
    HttpResponse,
    HttpServer,
    post,
    Responder,
    web
};

use actix_web::middleware::Logger;
use actix_web::web::Query;
use chrono::Duration;
use env_logger::{Env, init_from_env};
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use content_queue::sqs_content_queue::SQSContentQueue;
use fedineko_http_client::{construct_user_agent, GenericClient};
use fedineko_http_client::headers_signer_middleware::HeadersSignerMiddleware;
use fedineko_url_utils::required_url_from_config;
use lazy_activitypub::activity::Activity;
use lazy_activitypub::actor::Actor;
use lazy_activitypub::entity::{EntityType};
use lazy_activitypub::object::ObjectTrait;
use puprik::private_key::PrivateKey;
use crate::sink_task::SinkTaskContext;

use crate::webfinger::{
    get_webfinger_account,
    is_supported_user,
    WebFingerLink,
    WebFingerRequest,
    WebFingerResponse,
};

use crate::nodeinfo::{NodeInfo, NodeInfoRef};
use crate::sink::{Sink, SinkQueues};
use crate::utils::{make_server_actor, make_user_actor};

// Regular expression to extract key from signed requests.
// TODO: Should use pinnifed instead as it supports both
//       legacy and modern signatures.
static KEY_HOST_REGEX: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new("keyId=\"https?://(.+)#main-key\",")
        .case_insensitive(true)
        .build()
        .unwrap()
});

/// Application name to report in NodeInfo.
const APP_NAME: &str = "octofedi";

// Context for each web-server thread.
struct PerThreadContext {
    // This server instance address, e.g. https://fedineko.org.
    pub server_url: url::Url,

    // Server actor, it is the same actor that subscribes to relays.
    // Aliased e.g. as https://fedineko.org/actor.
    pub actor: Actor,

    // Sink for incoming activityPub activities.
    pub activities: Arc<Sink>,

    // Public key text to use when actor object is constructed.
    pub public_key_oneline: String,
}

// This route serves WebFinger information about account resources.
#[get("/.well-known/webfinger")]
async fn get_webfinger(
    context: web::Data<PerThreadContext>,
    query: Query<WebFingerRequest>,
) -> impl Responder {
    let req = query.into_inner();
    let server_host = context.server_url.host_str().unwrap();
    let account = get_webfinger_account(server_host, &req.resource);

    if account.is_none() {
        return HttpResponse::NotFound()
            .finish();
    }

    let account_name = account.unwrap();

    let link = match account_name {
        // loopback to server/actor
        "octofedi" => WebFingerLink::new_server_actor(&context.server_url),

        _ => WebFingerLink::new(
            &context.server_url,
            account_name,
        )
    };

    let about = WebFingerLink::new_about(&context.server_url);

    let alias = link.href.clone();

    let response = WebFingerResponse {
        aliases: vec![alias],
        subject: format!("acct:{account_name}@{server_host}"),
        links: vec![link, about],
    };

    HttpResponse::Ok()
        .content_type("application/jrd+json")
        .json(response)
}

// Helper function to get information about peer that probed
// either WebFinger or NodeInfo routes.
//
// `req` is [HttpRequest] to get peer details from.
fn get_probed_by(req: &HttpRequest) -> String {
    req.headers()
        .get("signature")
        .and_then(|header| header.to_str().ok())
        .and_then(|s| KEY_HOST_REGEX.captures(s))
        .map(|captures| {
            captures.get(1).unwrap().as_str().to_string()
        })
        .or_else(|| req.connection_info()
            .realip_remote_addr()
            .map(|s| s.to_string())
        ).unwrap_or("unknown".to_string())
}

// This route serves NodeInfo information and provides links to
// actual node info.
#[get("/.well-known/nodeinfo")]
async fn get_nodeinfo_ref(
    req: HttpRequest,
    context: web::Data<PerThreadContext>,
) -> impl Responder {
    info!("well-known/nodeinfo: probed by {}", get_probed_by(&req));
    web::Json(NodeInfoRef::new(&context.server_url))
}

// This route serves NodeInfo data compliant with NodeInfo schema 2.1.
#[get("/nodeinfo/2.1")]
async fn get_nodeinfo_21(req: HttpRequest) -> impl Responder {
    info!("nodeinfo/2.1: probed by {}", get_probed_by(&req));

    let content_type =
        r#"application/json; profile="http://nodeinfo.diaspora.software/ns/schema/2.1#"; charset=utf-8"#;

    HttpResponse::Ok()
        .content_type(content_type)
        .json(NodeInfo::new(APP_NAME, "2.1"))
}

// This route serves NodeInfo data compliant with NodeInfo schema 2.0.
#[get("/nodeinfo/2.0")]
async fn get_nodeinfo_20(req: HttpRequest) -> impl Responder {
    info!("nodeinfo/2.0: probed by {}", get_probed_by(&req));

    let content_type =
        r#"application/json; profile="http://nodeinfo.diaspora.software/ns/schema/2.0#"; charset=utf-8"#;

    HttpResponse::Ok()
        .content_type(content_type)
        .json(NodeInfo::new(APP_NAME, "2.0"))
}

// This route serves server Actor details.
#[get("/actor")]
async fn get_server_actor(
    req: HttpRequest,
    context: web::Data<PerThreadContext>,
) -> impl Responder {
    info!("actor: probed by {}", get_probed_by(&req));

    HttpResponse::Ok()
        .content_type("application/activity+json; charset=utf-8")
        .json(context.actor.clone())
}

// This route serves server Actor followers details.
// Or more precise it denies access to it.
#[get("/actor/followers")]
async fn get_server_actor_followers() -> impl Responder {
    HttpResponse::Forbidden()
        .finish()
}

// This route serves server Actor following details.
// Or more precise it denies access to it.
#[get("/actor/following")]
async fn get_server_actor_following() -> impl Responder {
    HttpResponse::Forbidden()
        .finish()
}

// This helper structure is used below to deserialize request
// to user specific information.
#[derive(Deserialize)]
struct UserInfoRequest {
    username: String,
}

// This route serves user Actor details.
#[get("/u/{username}")]
async fn get_user(
    http_req: HttpRequest,
    path: web::Path<UserInfoRequest>,
    context: web::Data<PerThreadContext>,
) -> impl Responder {
    let req = path.into_inner();
    let probed_by = get_probed_by(&http_req);

    if !is_supported_user(&req.username) {
        warn!(
            "{probed_by} requested details of unknown user '{}'",
            req.username
        );

        return HttpResponse::NotFound()
            .finish();
    }

    let actor = make_user_actor(
        &context.server_url,
        req.username.clone(),
        &context.public_key_oneline,
    );

    info!("Sent actor details for {} requested by {probed_by}", req.username);

    HttpResponse::Ok()
        .content_type("application/activity+json; charset=utf-8")
        .json(actor)
}

// This function is used to process inbox, either shared or user-specific.
async fn process_inbox(
    req: HttpRequest,
    activity: web::Json<Activity>,
    context: web::Data<PerThreadContext>,
) -> HttpResponse {
    debug!(
        "INBOX: HTTP request headers: {:?}, activity: {activity:?}",
        req.headers()
    );

    let activity = activity.into_inner();

    match activity.entity_type() {
        EntityType::Announce |
        EntityType::Create |
        EntityType::Delete |
        EntityType::Update => {
            let inner_object_id = activity.inner_object_id()
                .map(|url| url.to_string())
                .unwrap_or("<unknown inner object id>".into());

            let inner_object_type = activity.inner_object_type();

            let host = activity.activity_id()
                .host_str().unwrap_or("<unknown>");

            // slightly shorter log message
            if inner_object_type == EntityType::Unknown &&
                activity.entity_type() == EntityType::Announce
            {
                info!(
                    "{host} => {}: {inner_object_id}",
                    activity.entity_type(),
                );
            } else {
                // otherwise slightly longer log message with object type.
                info!(
                    "{host} => {}: {inner_object_id} ({inner_object_type})",
                    activity.entity_type(),
                );
            }

            context.activities.push(activity, req);
        }

        EntityType::Accept |
        EntityType::Reject |
        EntityType::Follow => {
            let host = activity.activity_id()
                .host_str().unwrap_or("<unknown>");

            let inner_object_id = activity.inner_object_id()
                .map(|url| url.to_string())
                .unwrap_or("<unknown inner object id>".into());

            info!(
                "{host} => {} (subscribe activity): {inner_object_id}",
                activity.entity_type(),
            );

            context.activities.push(activity, req);
        }

        EntityType::Undo => {
            warn!(
                "{}: activity of type {} is not supported",
                activity.object_id(),
                activity.entity_type(),
            );
        }

        _ => {
            warn!(
                "{}: activity of type {} is not supported: payload = {:?}",
                activity.object_id(),
                activity.entity_type(),
                activity.object
            );
        }
    }

    HttpResponse::Accepted()
        .finish()
}

// This route serves shared inbox,
// it is server actor's inbox as well.
#[post("/inbox")]
async fn post_inbox(
    req: HttpRequest,
    activity: web::Json<Activity>,
    context: web::Data<PerThreadContext>,
) -> impl Responder {
    process_inbox(req, activity, context).await
}

// This route serves user specific inbox.
#[post("/u/{username}/inbox")]
async fn post_user_inbox(
    http_req: HttpRequest,
    path: web::Path<UserInfoRequest>,
    activity: web::Json<Activity>,
    context: web::Data<PerThreadContext>,
) -> impl Responder {
    let req = path.into_inner();
    let probed_by = get_probed_by(&http_req);

    if !is_supported_user(&req.username) {
        warn!(
            "{probed_by} attempted delivery to inbox of unknown user '{}'",
            req.username
        );

        return HttpResponse::NotFound()
            .finish();
    }

    process_inbox(http_req, activity, context).await
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    init_from_env(
        Env::default()
            .default_filter_or("info")
            .default_write_style_or("always")
    );

    // Load configuration from environment
    let host = env::var("OCTOFEDI_HOST")
        .unwrap_or("127.0.0.1".into());

    let port: u16 = env::var("OCTOFEDI_PORT")
        .unwrap_or("8004".into())
        .parse()
        .unwrap_or(8004);

    let document_queue_url = env::var("DOCUMENT_QUEUE_URL")
        .expect(
            "Required environment variable DOCUMENT_QUEUE_URL is not set, \
            cannot proceed without document queue details"
        );

    let document_queue_role = env::var("DOCUMENT_QUEUE_ROLE")
        .expect(
            "Required environment variable DOCUMENT_QUEUE_ROLE is not set, \
            cannot proceed without document queue details");

    let requests_queue_url = env::var("REQUESTS_QUEUE_URL")
        .expect(
            "Required environment variable REQUESTS_QUEUE_URL is not set, \
            cannot proceed without request queue details"
        );

    let requests_queue_role = env::var("REQUESTS_QUEUE_ROLE")
        .expect(
            "Required environment variable REQUESTS_QUEUE_ROLE is not set, \
            cannot proceed without request queue details"
        );

    let server_url = required_url_from_config(
        "FEDINEKO_URL",
        "http://127.0.0.1",
    );

    let server_private_key_path = env::var("OCTOFEDI_PRIVATE_KEY_PATH")
        .expect(
            "Private key to sign request is not set, \
            check OCTOFEDI_PRIVATE_KEY_PATH variable"
        );

    let server_public_key_path = env::var("OCTOFEDI_PUBLIC_KEY_PATH")
        .expect(
            "Public key is not set, check OCTOFEDI_PUBLIC_KEY_PATH variable"
        );

    let public_key_oneline = std::fs::read_to_string(
        server_public_key_path
    ).unwrap();

    let key_id = server_url.join("/actor#main-key").unwrap();

    let server_key = PrivateKey::rsa_key_from_file_path(
        &server_private_key_path,
        key_id.as_str(),
    ).unwrap();

    info!("Octofedi listens on {}:{}", host, port);
    info!("Document queue URL: {document_queue_url}");
    info!("Requests queue URL: {requests_queue_url}");

    let actor = make_server_actor(&server_url, &public_key_oneline);
    let user_agent = construct_user_agent(&server_url, "octofedi", "0.3.4");

    let client = GenericClient::new(
        vec![GenericClient::user_agent_header(&user_agent)],
        Some(Box::new(HeadersSignerMiddleware::new(server_key))),
    );

    let sink = Arc::new(Sink::new(server_url.clone()));

    let content_queue = SQSContentQueue::new(
        document_queue_url,
        document_queue_role,
    ).await;

    let requests_queue = SQSContentQueue::new(
        requests_queue_url,
        requests_queue_role,
    ).await;

    let sink_task = sink_task::SinkTask::new(
        SinkTaskContext {
            sink: sink.clone(),
            // TODO: replace hardcoded value with configurable.
            processing_interval: Duration::try_seconds(30).unwrap(),
            sink_queues: SinkQueues {
                content_queue,
                requests_queue,
            },
            client,
        }
    );

    let json_extractor_config = web::JsonConfig::default()
        // Maximum request payload size to avoid service overload.
        .limit(65535);

    HttpServer::new(move || {
        let context = PerThreadContext {
            server_url: server_url.clone(),
            actor: actor.clone(),
            activities: sink.clone(),
            public_key_oneline: public_key_oneline.clone(),
        };

        App::new()
            .service(get_webfinger)
            .service(get_nodeinfo_21)
            .service(get_nodeinfo_20)
            .service(get_nodeinfo_ref)
            .service(get_server_actor_followers)
            .service(get_server_actor_following)
            .service(get_server_actor)
            .service(get_user)
            .service(post_inbox)
            .app_data(json_extractor_config.clone())
            .app_data(web::Data::new(context))
            .wrap(Logger::new(r#"%a/%{r}a "%r" %s "%{User-Agent}i" %T"#))
    })
        .bind((host, port))?
        .run()
        .await?;

    match sink_task.cancel().await {
        Ok(_) => {}
        
        Err(err) => {
            error!("Failed to cancel sink task: {err:?}");
        }
    }

    Ok(())
}
