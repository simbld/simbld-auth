use sqlx::{Error, Row};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct MockClient {
    query_opt_result: Arc<Mutex<Option<Option<dyn Row<Database = ()>>>>>,
    query_one_result: Arc<Mutex<Option<Row>>>,
    query_result: Arc<Mutex<Option<Vec<Row>>>>,
    execute_result: Arc<Mutex<u64>>,
    current_call: Arc<Mutex<usize>>,
    sequential_clients: Arc<Mutex<Vec<MockClient>>>,
    is_closed_value: Arc<Mutex<bool>>,
}

impl MockClient {
    pub fn new() -> Self {
        MockClient {
            query_opt_result: Arc::new(Mutex::new(None)),
            query_one_result: Arc::new(Mutex::new(None)),
            query_result: Arc::new(Mutex::new(None)),
            execute_result: Arc::new(Mutex::new(1)),
            current_call: Arc::new(Mutex::new(0)),
            sequential_clients: Arc::new(Mutex::new(vec![])),
            is_closed_value: Arc::new(Mutex::new(false)),
        }
    }

    pub fn with_query_opt_result(result: Option<Row>) -> Self {
        let mut client = Self::new();
        *client.query_opt_result.lock().unwrap() = Some(result);
        client
    }

    pub fn with_query_one_result(result: Row) -> Self {
        let mut client = Self::new();
        *client.query_one_result.lock().unwrap() = Some(result);
        client
    }

    pub fn with_query_result(result: Vec<Row>) -> Self {
        let mut client = Self::new();
        *client.query_result.lock().unwrap() = Some(result);
        client
    }

    pub fn with_execute_result(rows_affected: u64) -> Self {
        let mut client = Self::new();
        *client.execute_result.lock().unwrap() = rows_affected;
        client
    }

    pub fn set_closed(&self, closed: bool) {
        *self.is_closed_value.lock().unwrap() = closed;
    }

    pub async fn query_opt(
        &self,
        _query: &str,
        _params: &[&(dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync)],
    ) -> Result<Option<Row>, Error> {
        if !self.sequential_clients.lock().unwrap().is_empty() {
            let current = *self.current_call.lock().unwrap();
            let clients = self.sequential_clients.lock().unwrap();
            if current < clients.len() {
                let result = clients[current].query_opt(_query, _params).await;
                *self.current_call.lock().unwrap() += 1;
                return result;
            }
        }

        match *self.query_opt_result.lock().unwrap() {
            Some(ref result) => Ok(result.clone()),
            None => panic!("MockClient::query_opt called, but no result was configured"),
        }
    }

    pub async fn query_one(
        &self,
        _query: &str,
        _params: &[&(dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync)],
    ) -> Result<Row, Error> {
        if !self.sequential_clients.lock().unwrap().is_empty() {
            let current = *self.current_call.lock().unwrap();
            let clients = self.sequential_clients.lock().unwrap();
            if current < clients.len() {
                let result = clients[current].query_one(_query, _params).await;
                *self.current_call.lock().unwrap() += 1;
                return result;
            }
        }

        match *self.query_one_result.lock().unwrap() {
            Some(ref result) => Ok(result.clone()),
            None => panic!("MockClient::query_one called but no result was configured"),
        }
    }

    pub async fn query(
        &self,
        _query: &str,
        _params: &[&(dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync)],
    ) -> Result<Vec<Row>, Error> {
        if !self.sequential_clients.lock().unwrap().is_empty() {
            let current = *self.current_call.lock().unwrap();
            let clients = self.sequential_clients.lock().unwrap();
            if current < clients.len() {
                let result = clients[current].query(_query, _params).await;
                *self.current_call.lock().unwrap() += 1;
                return result;
            }
        }

        match *self.query_result.lock().unwrap() {
            Some(ref result) => Ok(result.clone()),
            None => panic!("MockClient::query called but no result was configured"),
        }
    }

    pub async fn execute(
        &self,
        _query: &str,
        _params: &[&(dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync)],
    ) -> Result<u64, Error> {
        if !self.sequential_clients.lock().unwrap().is_empty() {
            let current = *self.current_call.lock().unwrap();
            let clients = self.sequential_clients.lock().unwrap();
            if current < clients.len() {
                let result = clients[current].execute(_query, _params).await;
                *self.current_call.lock().unwrap() += 1;
                return result;
            }
        }

        Ok(*self.execute_result.lock().unwrap())
    }

    pub async fn execute_raw(
        &self,
        _query: &str,
        _params: &[&(dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync)],
    ) -> Result<u64, Error> {
        // Reuse the same logic as execute
        Ok(*self.execute_result.lock().unwrap())
    }

    pub async fn prepare(&self, _query: &str) -> Result<sqlx::postgres::PgStatement<'_>, Error> {
        // Return a stub Statement - note: this might need adjustment based on actual usage
        panic!("prepare not fully implemented for mock")
    }

    pub async fn prepare_typed(
        &self,
        _query: &str,
        _types: &[sqlx::postgres::PgTypeInfo],
    ) -> Result<sqlx::postgres::PgStatement<'_>, Error> {
        // Return a stub Statement - note: this might need adjustment based on actual usage
        panic!("prepare_typed not fully implemented for mock")
    }

    pub async fn query_raw(
        &self,
        _query: &str,
        _params: &[&(dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync)],
    ) -> Result<Vec<Row>, Error> {
        // Reuse the same logic as a query
        self.query("", &[]).await
    }

    pub fn is_closed(&self) -> bool {
        *self.is_closed_value.lock().unwrap()
    }

    pub async fn begin(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, Error> {
        // This is a simplification as we can't create a real Transaction in a mock
        panic!("Transaction is not implemented in MockClient");
    }

    pub async fn batch_execute(&self, _query: &str) -> Result<(), Error> {
        // Return success
        Ok(())
    }

    pub async fn simple_query(&self, _query: &str) -> Result<Vec<u8>, Error> {
        // Return an empty vector as a stub
        Ok(vec![])
    }

    // Helper function to create a mock Row - Note: Creating rows manually is complex in sqlx
    // This is a simplified version and might need adjustment based on an actual sqlx version
    pub fn create_mock_user_row(id: &str, provider_name: String, provider_user_id: &str) -> Row {
        // Note: Creating Row instances manually in sqlx is not straightforward
        // You might need to use a different approach or actual database queries for testing
        panic!("Creating mock rows manually is not supported in sqlx. Consider using a test database instead.")
    }

    pub fn create_mock_row_with_exists(exists: bool) -> Row {
        // Note: Creating Row instances manually in sqlx is not straightforward
        // You might need to use a different approach or actual database queries for testing
        panic!("Creating mock rows manually is not supported in sqlx. Consider using a test database instead.")
    }

    pub fn create_sequential_mock_client(clients: Vec<MockClient>) -> MockClient {
        let result = MockClient {
            query_opt_result: Arc::new(Mutex::new(None)),
            query_one_result: Arc::new(Mutex::new(None)),
            query_result: Arc::new(Mutex::new(None)),
            execute_result: Arc::new(Mutex::new(0)),
            current_call: Arc::new(Mutex::new(0)),
            sequential_clients: Arc::new(Mutex::new(clients)),
            is_closed_value: Arc::new(Mutex::new(false)),
        };
        result
    }
}
