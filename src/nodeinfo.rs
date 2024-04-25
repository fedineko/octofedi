use std::collections::HashMap;

use serde::Serialize;

// Yet another lacking implementation, now of NodeInfo.
//
// See:
// - https://codeberg.org/fediverse/fep/src/branch/main/fep/f1d5/fep-f1d5.md
// - https://github.com/jhass/nodeinfo/blob/main/schemas/2.1/schema.json

/// Represents reference to NodeInfo resource.
#[derive(Serialize)]
pub(crate) struct NodeInfoLink {
    /// Relation.
    pub rel: String,
    /// Link to resource.
    pub href: url::Url,
}

impl NodeInfoLink {
    /// Constructs new instance of [NodeInfoLink] with base URL `server_url`
    /// and `schema_version` matching one of well known (e.g. 2.0, 2.1).
    pub fn new(server: &url::Url, schema_version: &str) -> Self {
        let rel = format!(
            "http://nodeinfo.diaspora.software/ns/schema/{schema_version}"
        );

        let nodeinfo_path = format!("/nodeinfo/{schema_version}");
        let href = server.join(&nodeinfo_path).unwrap();

        Self {
            rel,
            href,
        }
    }
}

/// Helper structure to keep array of links.
#[derive(Serialize)]
pub(crate) struct NodeInfoRef {
    pub links: Vec<NodeInfoLink>,
}

impl NodeInfoRef {
    /// Constructs new instance of [NodeInfoRef] with links to
    /// both 2.0 nd 2.1 Diaspora schemas, located on `server_url`.
    pub fn new(server: &url::Url) -> Self {
        Self {
            links: vec![
                NodeInfoLink::new(server, "2.0"),
                NodeInfoLink::new(server, "2.1"),
            ]
        }
    }
}

/// This structure is used to declare software running this
/// Fediverse instance.
#[derive(Serialize)]
pub(crate) struct Software {
    /// Canonical name of the software.
    /// In case of Fedineko it is "octofedi".
    pub name: String,

    /// Version of the software.
    pub version: String,
}

/// Third-party services this instance could connect to.
/// octofedi does not declare anything here.
#[derive(Serialize, Default)]
pub(crate) struct Services {
    /// Services this instance could get traffic from.
    pub inbound: Vec<String>,

    /// Services this instance could publish to.
    pub outbound: Vec<String>,
}

/// Aggregated data about users on this instance.
/// Is not really applicable to Fedineko, still octofedi
/// provides somewhat reasonable values here.
#[derive(Serialize)]
pub(crate) struct Users {
    /// Total number of users.
    pub total: usize,

    /// Number of users being signed in at least once last month.
    #[serde(rename = "activeMonth")]
    pub active_month: usize,

    /// Number of users being signed in at least once last six months.
    #[serde(rename = "activeHalfyear")]
    pub active_half_year: usize,
}

impl Default for Users {
    fn default() -> Self {
        Self {
            total: 1,
            active_month: 1,
            active_half_year: 1,
        }
    }
}

/// Usage statistics for instance.
#[derive(Serialize, Default)]
pub(crate) struct Usage {
    /// Aggregated data about active users.
    pub users: Users,

    /// Number of posts generated by this instance.
    /// Zero in case of Fedineko.
    /// Though this could change, tracking these numbers is a hassle.
    #[serde(rename = "localPosts")]
    pub local_posts: usize,

    /// Number of comments generated by this instance.
    /// Zero in case of Fedineko.
    /// Though this could change, tracking these numbers is unlikely to happen.
    #[serde(rename = "localComments")]
    pub local_comments: usize,
}

/// Top-level structure for NodeInfo.
#[derive(Serialize)]
pub(crate) struct NodeInfo {
    /// NodeInfo schema version, e.g. 2.0 or 2.1.
    pub version: String,

    /// Application running the service.
    pub software: Software,

    /// Supported protocols, ActivityPub is the only one for octofedi.
    pub protocols: Vec<String>,

    /// Third party services this instance is capable to communicate with
    /// on behalf of user.
    pub services: Services,

    /// Flag to indicate ability for user to register on this instance.
    /// octofedi as well as Fedineko in general do not allow registrations.
    #[serde(rename = "openRegistrations")]
    pub open_registrations: bool,

    /// Usage metadata.
    /// As it is not really applicable to octofedi, defaults to some
    /// more or less reasonable values.
    pub usage: Usage,

    /// Instance meta-data.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl NodeInfo {
    fn str_to_value(s: &str) -> serde_json::Value {
        serde_json::Value::String(s.to_string())
    }

    /// This method returns instance meta-data including
    /// contact information. Values are hard-coded for now.
    pub fn metadata() -> HashMap<String, serde_json::Value> {
        let maintainer = HashMap::from([
            ("name", "Fedineko Support"),
            ("email", "support@fedineko.org"),
        ]);

        let admins_meta = serde_json::to_value(
            [maintainer.clone()]
        ).unwrap();

        let maintainer_meta =  serde_json::to_value(
            maintainer
        ).unwrap();

        HashMap::from([
            ("nodeName", Self::str_to_value("Fedineko")),
            (
                "nodeDescription", Self::str_to_value(
                "Fedineko indexing service. See https://fedineko.org/about")
            ),
            ("nodeAdmins", admins_meta),
            ("maintainer", maintainer_meta)
        ]).into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }

    /// Constructs new instance of [NodeInfo] with `app` being
    /// exposed in Software section, `schema_version` declared as
    /// NodeInfo version. Version of `app` is hard-coded here, it should not.
    pub fn new(app: &str, schema_version: &str) -> Self {
        Self {
            version: schema_version.to_string(),
            software: Software {
                name: app.to_string(),
                version: "0.3.4-rs".to_string(),
            },
            protocols: vec!["activitypub".into()],
            services: Services::default(),
            open_registrations: false,
            usage: Usage::default(),
            metadata: Self::metadata()
        }
    }
}