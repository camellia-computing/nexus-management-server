CREATE INDEX billing_invoices_open_due_idx
    ON public.billing_invoices (due_at, id)
    WHERE status = 'open';
