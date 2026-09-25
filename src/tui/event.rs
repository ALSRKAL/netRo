//! Input event thread and application events.
//!
//! Crossterm events are read on a dedicated thread so the render loop is never
//! blocked waiting for input.

use crossterm::event::{self, Event, KeyEvent, MouseEvent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
pub enum AppEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
    /// Periodic tick used for spinners, freshness labels and auto-refresh.
    Tick,
}

pub fn spawn_input_thread(
    stop: Arc<AtomicBool>,
    tick: Duration,
) -> (Receiver<AppEvent>, Sender<()>) {
    let (tx, rx) = channel::<AppEvent>();
    let (_wake_tx, wake_rx) = channel::<()>();
    std::thread::spawn(move || loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let has_event = match event::poll(tick) {
            Ok(value) => value,
            Err(_) => break,
        };
        if has_event {
            match event::read() {
                Ok(Event::Key(key)) => {
                    if tx.send(AppEvent::Key(key)).is_err() {
                        break;
                    }
                }
                Ok(Event::Mouse(mouse)) => {
                    if tx.send(AppEvent::Mouse(mouse)).is_err() {
                        break;
                    }
                }
                Ok(Event::Resize(width, height)) => {
                    if tx.send(AppEvent::Resize(width, height)).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        } else if tx.send(AppEvent::Tick).is_err() {
            break;
        }
        // The wake channel lets the main thread interrupt the poll promptly on
        // shutdown without waiting for the full tick interval.
        match wake_rx.try_recv() {
            Ok(()) => break,
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {}
        }
    });
    (rx, _wake_tx)
}

/// Receive the next event with a timeout, used to cap the redraw rate.
pub fn recv_timeout(rx: &Receiver<AppEvent>, timeout: Duration) -> Option<AppEvent> {
    match rx.recv_timeout(timeout) {
        Ok(event) => Some(event),
        Err(RecvTimeoutError::Timeout) => None,
        Err(RecvTimeoutError::Disconnected) => None,
    }
}
