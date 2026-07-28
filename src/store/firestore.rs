use async_trait::async_trait;
use chrono::Utc;

use ::firestore::FirestoreDb;
use ::firestore::errors::FirestoreError;

use crate::store::{StoreError, UserStore};
use crate::user::{NewUser, User};

const USERS_COLLECTION: &str = "users";

pub struct FirestoreUserStore {
    db: FirestoreDb,
}

impl FirestoreUserStore {
    pub fn new(db: FirestoreDb) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserStore for FirestoreUserStore {
    async fn create_user(&self, new_user: NewUser) -> Result<User, StoreError> {
        let user = User {
            email: new_user.email,
            password_hash: new_user.password_hash,
            created_at: Utc::now(),
        };

        self.db
            .fluent()
            .insert()
            .into(USERS_COLLECTION)
            .document_id(&user.email)
            .object(&user)
            .execute::<User>()
            .await
            .map_err(|err| match err {
                FirestoreError::DataConflictError(_) => StoreError::DuplicateEmail,
                other => StoreError::Backend(other.to_string()),
            })
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, StoreError> {
        self.db
            .fluent()
            .select()
            .by_id_in(USERS_COLLECTION)
            .obj::<User>()
            .one(email)
            .await
            .map_err(|err| StoreError::Backend(err.to_string()))
    }
}
