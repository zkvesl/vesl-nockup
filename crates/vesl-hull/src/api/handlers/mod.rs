//! HTTP handlers for the hull's stock routes.
//!
//! Each handler lives in its own file so adding or modifying one is a
//! self-contained edit. `super::router::stock_routes` wires them into
//! the axum [`Router`](axum::Router).

pub(super) mod commit;
pub(super) mod health;
pub(super) mod settle;
pub(super) mod status;
pub(super) mod verify;
