use std::sync::{Arc, Mutex};
use tokio_postgres::row::RowIter;
use tokio_postgres::types::ToSql;
use tokio_postgres::Transaction;
use tokio_postgres::{Column, Error, Row, Statement, ToStatement, Type};

#[derive(Clone)]
pub struct MockClient {
    query_opt_result: Arc<Mutex<Option<Option<Row>>>>,
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
        _params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
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
            None => panic!("MockClient::query_opt called but no result was configured"),
        }
    }

    pub async fn query_one(
        &self,
        _query: &str,
        _params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
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
        _params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
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
        _params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
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

    pub async fn execute_raw<T: ToStatement + Sync>(
        &self,
        _statement: &T,
        _params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<u64, Error> {
        // Reuse the same logic as execute
        Ok(*self.execute_result.lock().unwrap())
    }

    pub async fn prepare(&self, _query: &str) -> Result<Statement, Error> {
        // Return a stub Statement
        Ok(Statement::new("stub".to_string(), 0, vec![], vec![], None))
    }

    pub async fn prepare_typed(&self, _query: &str, _types: &[Type]) -> Result<Statement, Error> {
        // Return a stub Statement
        Ok(Statement::new("stub".to_string(), 0, vec![], vec![], None))
    }

    pub async fn query_raw<T: ToStatement + Sync>(
        &self,
        _statement: &T,
        _params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
        // Reuse the same logic as query
        self.query("", &[]).await
    }

    pub fn is_closed(&self) -> bool {
        *self.is_closed_value.lock().unwrap()
    }

    pub async fn transaction(&self) -> Result<Transaction<'_>, Error> {
        // This is a simplification as we can't actually create a real Transaction in a mock
        panic!("Transaction not implemented in MockClient");
    }

    pub async fn batch_execute(&self, _query: &str) -> Result<(), Error> {
        // Simply return success
        Ok(())
    }

    pub async fn simple_query(&self, _query: &str) -> Result<Vec<u8>, Error> {
        // Return empty vector as a stub
        Ok(vec![])
    }

    // Helper function to create a mock Row
    pub fn create_mock_user_row(id: &str, provider_name: String, provider_user_id: &str) -> Row {
        let column_names = vec!["id", "provider_name", "provider_user_id"];
        let column_types = vec![Type::TEXT, Type::TEXT, Type::TEXT];
        let columns: Vec<Column> = column_names
            .iter()
            .enumerate()
            .map(|(i, name)| Column::new(name.to_string(), column_types[i].clone()))
            .collect();

        let values: Vec<Box<dyn ToSql + Sync>> = vec![
            Box::new(id.to_string()),
            Box::new(provider),
            Box::new(provider_user_id.to_string()),
        ];

        Row::new(columns, values)
    }

    pub fn create_mock_row_with_exists(exists: bool) -> Row {
        let column_names = vec!["exists"];
        let column_types = vec![Type::BOOL];
        let columns: Vec<Column> = column_names
            .iter()
            .enumerate()
            .map(|(i, name)| Column::new(name.to_string(), column_types[i].clone()))
            .collect();

        let values: Vec<Box<dyn ToSql + Sync>> = vec![Box::new(exists)];

        Row::new(columns, values)
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
