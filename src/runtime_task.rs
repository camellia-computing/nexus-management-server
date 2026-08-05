use std::{fmt::Display, io};

use tokio::{
    sync::watch,
    task::{JoinError, JoinHandle},
};

pub async fn supervise_required_task<E>(
    name: &'static str,
    task: JoinHandle<Result<(), E>>,
    shutdown: watch::Sender<bool>,
    observed_shutdown: watch::Receiver<bool>,
) -> io::Result<()>
where
    E: Display,
{
    let result = match task.await {
        Ok(Ok(())) if *observed_shutdown.borrow() => Ok(()),
        Ok(Ok(())) => Err(io::Error::other(format!(
            "required runtime task {name} exited unexpectedly"
        ))),
        Ok(Err(error)) => Err(io::Error::other(format!(
            "required runtime task {name} failed: {error}"
        ))),
        Err(error) => Err(join_error(name, error)),
    };
    if result.is_err() && !*observed_shutdown.borrow() {
        tracing::error!(
            runtime_task = name,
            "required runtime task failed; requesting process shutdown"
        );
        let _ = shutdown.send(true);
    }
    result
}

pub async fn join_required_task(
    name: &'static str,
    task: JoinHandle<io::Result<()>>,
) -> io::Result<()> {
    match task.await {
        Ok(result) => result,
        Err(error) => Err(join_error(name, error)),
    }
}

fn join_error(name: &'static str, error: JoinError) -> io::Error {
    io::Error::other(format!(
        "required runtime task {name} could not be joined: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unexpected_required_task_exit_requests_shutdown() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async { Ok::<(), io::Error>(()) });

        let error = supervise_required_task("test-task", task, shutdown_tx, shutdown_rx.clone())
            .await
            .expect_err("unexpected exit must fail");

        assert!(error.to_string().contains("exited unexpectedly"));
        assert!(*shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn required_task_can_exit_after_shutdown() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        shutdown_tx.send(true).expect("shutdown receiver");
        let task = tokio::spawn(async { Ok::<(), io::Error>(()) });

        supervise_required_task("test-task", task, shutdown_tx, shutdown_rx)
            .await
            .expect("shutdown exit");
    }

    #[tokio::test]
    async fn required_task_error_requests_shutdown() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async { Err::<(), _>(io::Error::other("listener failed")) });

        let error = supervise_required_task("test-task", task, shutdown_tx, shutdown_rx.clone())
            .await
            .expect_err("task error must fail");

        assert!(error.to_string().contains("listener failed"));
        assert!(*shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn required_task_panic_requests_shutdown() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async {
            panic!("test task panic");
            #[allow(unreachable_code)]
            Ok::<(), io::Error>(())
        });

        let error = supervise_required_task("test-task", task, shutdown_tx, shutdown_rx.clone())
            .await
            .expect_err("panic must fail");

        assert!(error.to_string().contains("could not be joined"));
        assert!(*shutdown_rx.borrow());
    }
}
