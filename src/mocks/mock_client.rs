// TODO: MockClient needs to be completely rewritten for sqlx instead of tokio_postgres
// This file is temporarily disabled until the database layer is standardized

// The original implementation used tokio_postgres::Row which is not compatible with sqlx
// When re-enabling, use sqlx test utilities or create mock implementations that work with sqlx types
