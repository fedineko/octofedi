use std::sync::Arc;
use chrono::Duration;
use log::info;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use fedineko_http_client::GenericClient;
use crate::sink::{Sink, SinkQueues};

/// Periodic task that triggers processing of accumulated sink items.
pub(crate) struct SinkTask {
    /// Token to cancel task.
    cancellation_token: CancellationToken,

    /// Handle to join and await completion of task.
    join_handle: JoinHandle<()>,
}

pub(crate) struct SinkTaskContext {
    ///  Sink to consume activities.
    pub sink: Arc<Sink>,

    /// Period of time between waking task for processing.
    pub processing_interval: Duration,

    /// Queues to use for pushing document messages.
    pub sink_queues: SinkQueues,

    /// HTTP client to fetch remote content.
    pub client: GenericClient,
}

impl SinkTask {
    /// Constructs new instance of [SinkTask] with given `background_context`.
    ///
    /// Typically single task only is needed in usual octofedi workflow.
    pub fn new(background_context: SinkTaskContext) -> Self {
        info!("Spawning sink task thread");

        let cancellation_token = CancellationToken::new();

        let join_handle = actix_rt::spawn(
            background_task_thread(
                background_context,
                cancellation_token.clone()
            )
        );

        Self {
            cancellation_token,
            join_handle,
        }
    }

    /// This method is used to cancel earlier spawned sink task.
    /// It will "block" on awaiting task finishing.
    pub async fn cancel(self) -> std::io::Result<()> {
        self.cancellation_token.cancel();
        self.join_handle.await?;
        Ok(())
    }
}

/// Sing task main logic. It is function executed periodically.
///
/// - `task_context` - sink task context with required parameters or data.
/// - `stop_signal` - cancellation token used by task to figure out if
///                   it is time to finish.
async fn background_task_thread(
    task_context: SinkTaskContext,
    stop_signal: CancellationToken,
) {
    let sleep_time = tokio::time::Duration::from_millis(
        task_context.processing_interval.num_milliseconds() as u64
    );

    loop {
        if task_context.sink.items() >= 10 {
            task_context.sink.process(
                &task_context.sink_queues,
                &task_context.client,
            ).await;
        }

        tokio::select! {
            _ = sleep(sleep_time) => {
                continue;
            }

            _ = stop_signal.cancelled() => {
                info!("Sink task shutdown");
                break;
            }
        }
    }
}