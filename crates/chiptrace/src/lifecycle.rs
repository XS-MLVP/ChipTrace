use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Boundary {
    Start,
    Terminal,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct LifecycleState {
    pub boundary_source: String,
    pub start_count: u64,
    pub terminal_count: u64,
    pub invalid_boundary_count: u64,
    pub latest_epoch_closed: bool,
    pub latest_boundary: Option<String>,
    pub latest_boundary_capture_id: Option<String>,
}

impl LifecycleState {
    pub fn new(boundary_source: &str) -> Self {
        Self {
            boundary_source: boundary_source.to_owned(),
            ..Self::default()
        }
    }

    pub fn observe_event(&mut self, event: &str, capture_id: &str, require_pair: bool) -> bool {
        let event = normalize_event(event);
        let boundary = if is_start_event(&event) {
            Boundary::Start
        } else if is_terminal_event(&event) {
            Boundary::Terminal
        } else {
            return false;
        };
        self.observe(boundary, &event, capture_id, require_pair);
        matches!(boundary, Boundary::Terminal)
    }

    pub fn observe(
        &mut self,
        boundary: Boundary,
        event: &str,
        capture_id: &str,
        require_pair: bool,
    ) {
        match boundary {
            Boundary::Start => {
                if require_pair && self.start_count > self.terminal_count {
                    self.invalid_boundary_count = self.invalid_boundary_count.saturating_add(1);
                }
                self.start_count = self.start_count.saturating_add(1);
                self.latest_epoch_closed = false;
            }
            Boundary::Terminal => {
                self.terminal_count = self.terminal_count.saturating_add(1);
                if require_pair && self.start_count < self.terminal_count {
                    self.invalid_boundary_count = self.invalid_boundary_count.saturating_add(1);
                    self.latest_epoch_closed = false;
                } else {
                    self.latest_epoch_closed = true;
                }
            }
        }
        self.latest_boundary = Some(normalize_event(event));
        self.latest_boundary_capture_id = Some(capture_id.to_owned());
    }

    pub fn observe_final_snapshot(&mut self, capture_id: &str) {
        self.terminal_count = self.terminal_count.saturating_add(1);
        self.latest_epoch_closed = true;
        self.boundary_source = "final_snapshot".to_owned();
        self.latest_boundary = Some("final_snapshot".to_owned());
        self.latest_boundary_capture_id = Some(capture_id.to_owned());
    }
}

pub(crate) fn normalize_event(event: &str) -> String {
    event
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', ':'], "_")
}

pub(crate) fn is_start_event(event: &str) -> bool {
    matches!(
        normalize_event(event).as_str(),
        "session_start" | "session_started" | "task_start" | "task_started"
    )
}

pub(crate) fn is_terminal_event(event: &str) -> bool {
    let event = normalize_event(event);
    matches!(
        event.as_str(),
        "session_end"
            | "session_ended"
            | "task_end"
            | "task_ended"
            | "task_completed"
            | "cancel"
            | "cancelled"
            | "canceled"
            | "terminated"
            | "abort"
            | "aborted"
            | "abandoned"
    ) || event.starts_with("session_cancel")
        || event.starts_with("task_cancel")
        || event.starts_with("session_fail")
        || event.starts_with("task_fail")
}
