use crate::error::GateResult;
use crate::execute::AuthorizedExecutionRequest;
use crate::simulator::ExecutionAttempt;

pub trait TransactionalAuthorizer: Send + Sync {
    fn execute_authorized(
        &self,
        request: &AuthorizedExecutionRequest<'_>,
    ) -> GateResult<ExecutionAttempt>;
}
