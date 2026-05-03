-- Run once in Supabase SQL Editor, or call POST /api/create-table with DATABASE_URL set.

create table if not exists public.portfolios (

  id uuid default gen_random_uuid() primary key,

  user_id text not null,

  symbol text not null,

  shares numeric not null,

  avg_price numeric not null,

  buy_date date,

  buy_price numeric,

  created_at timestamp default now()

);



alter table public.portfolios add column if not exists buy_date date;

alter table public.portfolios add column if not exists buy_price numeric;

alter table public.portfolios add column if not exists status text default 'active';

alter table public.portfolios add column if not exists exit_price numeric;

alter table public.portfolios add column if not exists exit_date date;

alter table public.portfolios add column if not exists final_pnl numeric;

alter table public.portfolios add column if not exists currency text default 'INR';

alter table public.portfolios add column if not exists market text default 'NSE/BSE';



alter table public.portfolios enable row level security;



drop policy if exists "portfolios_select_own" on public.portfolios;

create policy "portfolios_select_own" on public.portfolios

  for select using (auth.uid()::text = user_id);



drop policy if exists "portfolios_insert_own" on public.portfolios;

create policy "portfolios_insert_own" on public.portfolios

  for insert with check (auth.uid()::text = user_id);



drop policy if exists "portfolios_update_own" on public.portfolios;

create policy "portfolios_update_own" on public.portfolios

  for update using (auth.uid()::text = user_id);



drop policy if exists "portfolios_delete_own" on public.portfolios;

create policy "portfolios_delete_own" on public.portfolios

  for delete using (auth.uid()::text = user_id);

