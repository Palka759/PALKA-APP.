-- PALKA 1.5.0: repair private media storage permissions and authenticated message access.
-- No access is granted to anon/public users for private chats or chat media.

insert into storage.buckets (id, name, public)
values ('chat-media', 'chat-media', false)
on conflict (id) do update set public = false;

drop policy if exists "Users upload own chat media" on storage.objects;
create policy "Users upload own chat media" on storage.objects
for insert to authenticated
with check (bucket_id = 'chat-media' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "Users read chat media" on storage.objects;
create policy "Users read chat media" on storage.objects
for select to authenticated
using (bucket_id = 'chat-media');

grant usage on schema public to authenticated;
grant select, insert, update on public.profiles to authenticated;
grant select, insert on public.conversations to authenticated;
grant select, insert, update, delete on public.messages to authenticated;
grant select, insert, update, delete on public.message_reactions to authenticated;
grant select, insert, update, delete on public.pinned_messages to authenticated;
grant select, insert, update, delete on public.chat_typing to authenticated;
grant select, insert, update, delete on public.user_blocks, public.private_notes to authenticated;
grant select, insert, update, delete on storage.objects to authenticated;
grant update (read_at) on public.messages to authenticated;

drop policy if exists "members mark incoming messages read" on public.messages;
create policy "members mark incoming messages read" on public.messages
for update to authenticated
using (
  sender_id <> auth.uid()
  and exists (
    select 1 from public.conversations c
    where c.id = messages.conversation_id
      and auth.uid() in (c.member_one, c.member_two)
  )
)
with check (
  sender_id <> auth.uid()
  and exists (
    select 1 from public.conversations c
    where c.id = messages.conversation_id
      and auth.uid() in (c.member_one, c.member_two)
  )
);
