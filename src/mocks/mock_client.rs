use async_trait::async_trait;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Error, Row};

pub struct MockClient;

#[async_trait]
impl tokio_postgres::GenericClient for MockClient {
  async fn prepare(self, _query: str) -> Result<tokio_postgres::Statement, ()> {
    // Return a fake statement
    Err(Error::new(DbError::new(SqlState::UNDEFINED_FUNCTION, "Undefined function")));
    async fn execute<T>(
      &self,
      _statement: &T,
      _params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error>
    where
      T: ?Sized + tokio_postgres::ToStatement + Sync + Send,
    {
      Ok(0)
    }

    async fn execute_raw(
      &self,
      _query: &str,
      _params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error> {
      Ok(0)
    }

    async fn query_one<T>(
      &self,
      _statement: &T,
      _params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error>
    where
      T: ?Sized + tokio_postgres::ToStatement + Sync + Send,
    {
      Err(tokio_postgres::Error::new(tokio_postgres::error::DbError::new(
        tokio_postgres::error::SqlState::NO_DATA,
        "No row",
      )))
    }

    async fn query_raw(
      &self,
      _query: &str,
      _params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
      Ok(vec![])
    }

    async fn query_typed<T>(
      &self,
      _statement: &T,
      _params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error>
    where
      T: ?Sized + tokio_postgres::ToStatement + Sync + Send,
    {
      Ok(vec![])
    }

    async fn query_typed_raw(
      &self,
      _query: &str,
      _params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
      Ok(vec![])
    }

    async fn prepare_typed(
      &self,
      _query: &str,
      _param_types: &[tokio_postgres::types::Type],
    ) -> Result<tokio_postgres::Statement, Error> {
      Err(Error::new(DbError::new(SqlState::UNDEFINED_FUNCTION, "Undefined function")))
    }

    async fn transaction(&self) -> Result<tokio_postgres::Transaction<'_>, Error> {
      Err(Error::new(DbError::new(SqlState::UNDEFINED_FUNCTION, "Undefined function")))
    }

    async fn batch_execute(&self, _query: &str) -> Result<(), Error> {
      Ok(())
    }

    async fn simple_query(
      &self,
      _query: &str,
    ) -> Result<Vec<tokio_postgres::SimpleQueryMessage>, Error> {
      Ok(vec![])
    }

    fn client(&self) -> &tokio_postgres::Client {
      unimplemented!()
    }
  }

  /// Basic query method that returns an empty result.
  async fn query(self, query: str, _params: [(dyn ToSql + Sync)]) -> Result<Vec<Row>, Error> {
    if query.contains("SELECT") {
      // simulating the absence of results
      Ok(vec![]);
    } else {
      Err(Error::new(DbError::new(SqlState::UNDEFINED_FUNCTION, "Undefined function")))
    }
  }
  async fn query_one(self, _query: str, _params: [(dyn ToSql + Sync)]) -> Result<Row, Error> {
    Err(tokio_postgres::Error::new(tokio_postgres::error::DbError::new(
      tokio_postgres::error::SqlState::NO_DATA,
      "No row",
    )))
  }
}
