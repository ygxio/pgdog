use std::collections::BTreeSet;

use crate::{Config, Error, ServerAuth, User, Users};

enum Databases {
    All,
    List(BTreeSet<String>),
}

impl Databases {
    fn overlaps(&self, user: &User) -> bool {
        match self {
            Self::All => true,
            Self::List(databases) => databases.iter().any(|database| user.has_database(database)),
        }
    }
}

impl Users {
    pub fn check_virtual(&self) -> Result<(), Error> {
        self.users
            .iter()
            .filter_map(|user| Some((user, user.virtual_of.as_deref()?)))
            .try_for_each(|(user, parent)| self.check_virtual_user(user, parent))
    }

    pub fn resolve_virtual(&mut self, config: &Config) {
        let inherited: Vec<_> = self
            .users
            .iter()
            .map(|user| match user.virtual_of.as_deref() {
                Some(parent) if explicit_databases(user).is_empty() => {
                    Some(self.parent_databases(parent))
                }
                _ => None,
            })
            .collect();

        for (user, databases) in self.users.iter_mut().zip(inherited) {
            match databases {
                Some(Databases::All) => {
                    let mut databases: Vec<_> = config.databases().into_keys().collect();
                    databases.sort();
                    user.databases = databases;
                }
                Some(Databases::List(databases)) => {
                    user.databases = databases.into_iter().collect()
                }
                None => (),
            }
        }
    }

    fn check_virtual_user(&self, user: &User, parent: &str) -> Result<(), Error> {
        let error = |reason: String| {
            Err(Error::ParseError(format!(
                r#"virtual user "{}": {}"#,
                user.name, reason
            )))
        };

        if parent == user.name {
            return error("\"virtual_of\" can't reference itself".into());
        }

        let parents: Vec<_> = self.users.iter().filter(|u| u.name == parent).collect();

        if parents.is_empty() {
            return error(format!(r#"user "{parent}" in "virtual_of" doesn't exist"#));
        }

        if parents.iter().any(|parent| parent.is_virtual()) {
            return error(format!(
                r#"user "{parent}" in "virtual_of" is a virtual user itself"#
            ));
        }

        if let Some(field) = forbidden_field(user) {
            return error(format!(
                r#""{field}" can't be set, it's inherited from user "{parent}""#
            ));
        }

        let explicit = explicit_databases(user);

        if let Some(database) = explicit
            .iter()
            .find(|database| !parents.iter().any(|parent| parent.has_database(database)))
        {
            return error(format!(
                r#"database "{database}" isn't configured for user "{parent}""#
            ));
        }

        let databases = if explicit.is_empty() {
            self.parent_databases(parent)
        } else {
            Databases::List(
                explicit
                    .iter()
                    .map(|database| database.to_string())
                    .collect(),
            )
        };

        if self.users.iter().any(|other| {
            other.name == user.name && !other.is_virtual() && databases.overlaps(other)
        }) {
            return error("a regular user with the same name exists for the same database".into());
        }

        Ok(())
    }

    fn parent_databases(&self, parent: &str) -> Databases {
        let parents = self
            .users
            .iter()
            .filter(|user| user.name == parent && !user.is_virtual());
        let mut databases = BTreeSet::new();

        for user in parents {
            if user.all_databases {
                return Databases::All;
            }
            databases.extend(explicit_databases(user).into_iter().map(str::to_owned));
        }

        Databases::List(databases)
    }
}

fn explicit_databases(user: &User) -> Vec<&str> {
    if !user.databases.is_empty() {
        user.databases.iter().map(String::as_str).collect()
    } else if !user.database.is_empty() {
        vec![user.database.as_str()]
    } else {
        vec![]
    }
}

fn forbidden_field(user: &User) -> Option<&'static str> {
    let role = &user.role_config;

    [
        ("server_password", user.server_password.is_some()),
        ("server_auth", user.server_auth != ServerAuth::Password),
        ("server_iam_region", user.server_iam_region.is_some()),
        (
            "server_iam_assume_role",
            user.server_iam_assume_role.is_some(),
        ),
        ("server_vault_path", user.server_vault_path.is_some()),
        (
            "vault_refresh_percent",
            user.vault_refresh_percent.is_some(),
        ),
        ("pool_size", user.pool_size.is_some()),
        ("min_pool_size", user.min_pool_size.is_some()),
        ("pool_size_primary", role.pool_size_primary.is_some()),
        ("pool_size_replica", role.pool_size_replica.is_some()),
        (
            "min_pool_size_primary",
            role.min_pool_size_primary.is_some(),
        ),
        (
            "min_pool_size_replica",
            role.min_pool_size_replica.is_some(),
        ),
        ("idle_timeout_primary", role.idle_timeout_primary.is_some()),
        ("idle_timeout_replica", role.idle_timeout_replica.is_some()),
        ("pooler_mode", user.pooler_mode.is_some()),
        ("server_lifetime", user.server_lifetime.is_some()),
        (
            "server_lifetime_jitter",
            user.server_lifetime_jitter.is_some(),
        ),
        ("idle_timeout", user.idle_timeout.is_some()),
        ("replication_mode", user.replication_mode),
        ("replication_sharding", user.replication_sharding.is_some()),
        ("schema_admin", user.schema_admin),
        ("all_databases", user.all_databases),
    ]
    .into_iter()
    .find_map(|(field, set)| set.then_some(field))
}

#[cfg(test)]
mod test {
    use super::*;

    fn users(toml: &str) -> Users {
        toml::from_str(toml).unwrap()
    }

    fn check_error(toml: &str) -> String {
        users(toml).check_virtual().unwrap_err().to_string()
    }

    const PARENT: &str = r#"
[[users]]
name = "pgdog"
database = "prod"
server_user = "postgres"
server_auth = "rds_iam"
pool_size = 50
"#;

    #[test]
    fn test_parse_virtual_of() {
        let users = users(&format!(
            r#"{PARENT}
[[users]]
name = "user_one"
virtual_of = "pgdog"
password = "a"
"#
        ));

        assert_eq!(users.users[0].virtual_of, None);
        assert!(!users.users[0].is_virtual());
        assert_eq!(users.users[1].virtual_of.as_deref(), Some("pgdog"));
        assert!(users.users[1].is_virtual());
    }

    #[test]
    fn test_role_name() {
        let users = users(&format!(
            r#"{PARENT}
[[users]]
name = "user_one"
virtual_of = "pgdog"

[[users]]
name = "user_two"
virtual_of = "pgdog"
server_user = "analytics"
"#
        ));

        assert_eq!(users.users[1].role_name(), "user_one");
        assert_eq!(users.users[2].role_name(), "analytics");
    }

    #[test]
    fn test_check_virtual_ok() {
        let users = users(&format!(
            r#"{PARENT}
[[users]]
name = "user_one"
virtual_of = "pgdog"
password = "a"
server_user = "analytics"
statement_timeout = 5000
lock_timeout = 1000
read_only = true
"#
        ));

        users.check_virtual().unwrap();
    }

    #[test]
    fn test_check_virtual_missing_parent() {
        let error = check_error(
            r#"
[[users]]
name = "user_one"
virtual_of = "pgdog"
"#,
        );

        assert!(error.contains(r#"user "pgdog" in "virtual_of" doesn't exist"#));
    }

    #[test]
    fn test_check_virtual_self_reference() {
        let error = check_error(
            r#"
[[users]]
name = "user_one"
virtual_of = "user_one"
"#,
        );

        assert!(error.contains("can't reference itself"));
    }

    #[test]
    fn test_check_virtual_chain() {
        let error = check_error(&format!(
            r#"{PARENT}
[[users]]
name = "user_one"
virtual_of = "pgdog"

[[users]]
name = "user_two"
virtual_of = "user_one"
"#
        ));

        assert!(error.contains(r#"virtual user "user_two""#));
        assert!(error.contains("is a virtual user itself"));
    }

    #[test]
    fn test_check_virtual_forbidden_fields() {
        let fields = [
            ("server_password", r#""secret""#),
            ("server_auth", r#""rds_iam""#),
            ("server_iam_region", r#""us-east-1""#),
            ("server_iam_assume_role", r#""arn:aws:iam::1:role/r""#),
            ("server_vault_path", r#""database/creds/r""#),
            ("vault_refresh_percent", "50"),
            ("pool_size", "10"),
            ("min_pool_size", "1"),
            ("pool_size_primary", "10"),
            ("pool_size_replica", "10"),
            ("min_pool_size_primary", "1"),
            ("min_pool_size_replica", "1"),
            ("idle_timeout_primary", "1000"),
            ("idle_timeout_replica", "1000"),
            ("pooler_mode", r#""session""#),
            ("server_lifetime", "1000"),
            ("server_lifetime_jitter", "1000"),
            ("idle_timeout", "1000"),
            ("replication_mode", "true"),
            ("replication_sharding", r#""prod""#),
            ("schema_admin", "true"),
            ("all_databases", "true"),
        ];

        for (field, value) in fields {
            let error = check_error(&format!(
                r#"{PARENT}
[[users]]
name = "user_one"
virtual_of = "pgdog"
{field} = {value}
"#
            ));

            assert!(
                error.contains(&format!(
                    r#""{field}" can't be set, it's inherited from user "pgdog""#
                )),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn test_check_virtual_database_not_in_parent() {
        let error = check_error(&format!(
            r#"{PARENT}
[[users]]
name = "user_one"
virtual_of = "pgdog"
database = "staging"
"#
        ));

        assert!(error.contains(r#"database "staging" isn't configured for user "pgdog""#));
    }

    #[test]
    fn test_check_virtual_database_subset_of_parent() {
        let users = users(
            r#"
[[users]]
name = "pgdog"
databases = ["prod", "staging"]

[[users]]
name = "user_one"
virtual_of = "pgdog"
database = "staging"
"#,
        );

        users.check_virtual().unwrap();
    }

    #[test]
    fn test_check_virtual_database_from_parent_with_all_databases() {
        let users = users(
            r#"
[[users]]
name = "pgdog"
all_databases = true

[[users]]
name = "user_one"
virtual_of = "pgdog"
database = "anything"
"#,
        );

        users.check_virtual().unwrap();
    }

    #[test]
    fn test_check_virtual_name_clash_with_regular_user() {
        let error = check_error(&format!(
            r#"{PARENT}
[[users]]
name = "user_one"
database = "prod"
password = "a"

[[users]]
name = "user_one"
virtual_of = "pgdog"
"#
        ));

        assert!(error.contains("a regular user with the same name exists"));
    }

    #[test]
    fn test_check_virtual_same_name_different_database() {
        let users = users(&format!(
            r#"{PARENT}
[[users]]
name = "user_one"
database = "staging"
password = "a"

[[users]]
name = "user_one"
virtual_of = "pgdog"
"#
        ));

        users.check_virtual().unwrap();
    }

    #[test]
    fn test_resolve_virtual_inherits_database() {
        let mut users = users(&format!(
            r#"{PARENT}
[[users]]
name = "user_one"
virtual_of = "pgdog"
"#
        ));

        users.resolve_virtual(&Config::default());

        assert_eq!(users.users[1].databases, vec!["prod".to_string()]);
        assert!(users.users[1].has_database("prod"));
        assert!(users.users[0].databases.is_empty());
    }

    #[test]
    fn test_resolve_virtual_inherits_from_all_parent_entries() {
        let mut users = users(
            r#"
[[users]]
name = "pgdog"
database = "prod"

[[users]]
name = "pgdog"
databases = ["staging", "analytics"]

[[users]]
name = "user_one"
virtual_of = "pgdog"
"#,
        );

        users.resolve_virtual(&Config::default());

        assert_eq!(
            users.users[2].databases,
            vec![
                "analytics".to_string(),
                "prod".to_string(),
                "staging".to_string()
            ]
        );
    }

    #[test]
    fn test_resolve_virtual_expands_all_databases() {
        let config: Config = toml::from_str(
            r#"
[[databases]]
name = "staging"
host = "127.0.0.1"

[[databases]]
name = "prod"
host = "127.0.0.1"
"#,
        )
        .unwrap();
        let mut users = users(
            r#"
[[users]]
name = "pgdog"
all_databases = true

[[users]]
name = "user_one"
virtual_of = "pgdog"
"#,
        );

        users.resolve_virtual(&config);

        assert!(!users.users[1].all_databases);
        assert_eq!(
            users.users[1].databases,
            vec!["prod".to_string(), "staging".to_string()]
        );
        users.check_virtual().unwrap();
    }

    #[test]
    fn test_resolve_virtual_is_idempotent() {
        let mut users = users(&format!(
            r#"{PARENT}
[[users]]
name = "user_one"
virtual_of = "pgdog"
"#
        ));

        users.check_virtual().unwrap();
        users.resolve_virtual(&Config::default());
        let resolved = users.clone();

        users.check_virtual().unwrap();
        users.resolve_virtual(&Config::default());

        assert_eq!(users, resolved);
    }

    #[test]
    fn test_resolve_virtual_keeps_explicit_database() {
        let mut users = users(
            r#"
[[users]]
name = "pgdog"
databases = ["prod", "staging"]

[[users]]
name = "user_one"
virtual_of = "pgdog"
database = "staging"
"#,
        );

        users.resolve_virtual(&Config::default());

        assert_eq!(users.users[1].database, "staging");
        assert!(users.users[1].databases.is_empty());
        assert!(!users.users[1].all_databases);
    }
}
