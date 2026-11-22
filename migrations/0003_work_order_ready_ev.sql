-- Dispatch reads ready work orders in EV order; keep the 5k-backlog tick bounded.
CREATE INDEX IF NOT EXISTS ix_wo_ready_ev ON work_order(state, ev_cost DESC, created, id);
