use serde::{Deserialize, Serialize};

// A lacking implementation of WebFinger:
// see: <https://datatracker.ietf.org/doc/html/rfc7033>

/// This structure represents link to resource in WebFinger output.
#[derive(Serialize)]
pub(crate) struct WebFingerLink {
    /// Relation.
    pub rel: String,

    /// Content type of the referenced resource.
    #[serde(rename = "type")]
    pub typo: String,

    /// Resource reference
    pub href: url::Url,
}

impl WebFingerLink {
    /// Constructs new instance of self-referencing [WebFingerLink]
    /// using base `server_url` and `account_name` representing
    /// preferred username of actor.
    pub fn new(server_url: &url::Url, account_name: &str) -> Self {
        let user_path = format!("u/{account_name}");
        let href = server_url.join(&user_path).unwrap();

        Self {
            rel: "self".into(),
            typo: "application/activity+json".into(),
            href,
        }
    }

    /// Constructs new instance of profile-referencing [WebFingerLink]
    /// using base `server_url` to construct link to about page.
    pub fn new_about(
        server_url: &url::Url,
    ) -> Self {
        Self {
            rel: "http://webfinger.net/rel/profile-page".into(),
            typo: "text/html".into(),
            href: server_url.join("/about").unwrap(),
        }
    }

    /// Constructs new instance of self-referencing [WebFingerLink]
    /// using base `server_url`.
    pub fn new_server_actor(server_url: &url::Url) -> Self {
        let href = server_url.join("/actor").unwrap();

        Self {
            rel: "self".into(),
            typo: "application/activity+json".into(),
            href,
        }
    }
}

/// This structure wraps response to WebFinger requests.
#[derive(Serialize)]
pub(crate) struct WebFingerResponse {
    /// Subject response relates to.
    pub subject: String,

    /// Any aliases for the subject.
    pub aliases: Vec<url::Url>,

    /// Links such as self-references, profile page, etc.
    pub links: Vec<WebFingerLink>,
}

/// WebFinger requests to provide details about resource.
#[derive(Deserialize)]
pub(crate) struct WebFingerRequest {
    /// Resource to get details for. octofedi supports only "acct:" resources
    /// for accounts on this instance.
    pub resource: String,
}

/// Helper structure to keep pair username + server instance together.
pub(crate) struct WebFingerAccount<'a> {
    /// Preferred username, account name on this instance.
    pub username: &'a str,

    /// Server instance.
    pub server: &'a str,
}

impl<'a> WebFingerAccount<'a> {
    /// This method parses given `resource` string and returns
    /// more structured [WebFingerAccount] on success, empty Option on failure.
    pub fn parse(resource: &'a str) -> Option<Self> {
        if !resource.starts_with("acct:") {
            return None;
        }

        let parts: Vec<_> = resource[5..].split('@').collect();

        if parts.len() != 2 {
            return None;
        }

        Some(
            Self {
                username: parts.first().unwrap(),
                server: parts.get(1).unwrap(),
            }
        )
    }
}

/// Returns true if `username` matches any supported by `octofedi`.
pub(crate) fn is_supported_user(username: &str) -> bool {
    matches!(username,
        "nyah" |
        "support" |
        "octofedi"
    )
}

/// Parses given `resource` string and if it matches any supported account,
/// plus `server_host` matches this octofedi instance then return account name.
pub(crate) fn get_webfinger_account<'a>(
    server_host: &str,
    resource: &'a str,
) -> Option<&'a str> {
    if let Some(account) = WebFingerAccount::parse(resource) {
        if account.server != server_host {
            return None;
        }

        if is_supported_user(account.username) {
            return Some(account.username);
        }
    }

    None
}
