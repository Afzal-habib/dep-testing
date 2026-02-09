-- CreateTable
CREATE TABLE "attachments" (
    "id" UUID NOT NULL,
    "message_id" UUID NOT NULL,
    "channel_id" UUID NOT NULL,
    "mongo_uploader_id" TEXT NOT NULL,
    "file_name" TEXT NOT NULL,
    "file_url" TEXT,
    "s3_key" TEXT,
    "s3_bucket" TEXT,
    "file_size" INTEGER,
    "file_type" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "attachments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "channel_members" (
    "id" UUID NOT NULL,
    "channel_id" UUID NOT NULL,
    "mongo_member_id" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'member',
    "joined_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(6),
    "is_online" BOOLEAN NOT NULL DEFAULT false,
    "notifications_enabled" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "channel_members_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "channels" (
    "id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "name" TEXT,
    "avatar_url" TEXT,
    "mongo_department_id" TEXT,
    "mongo_project_id" TEXT,
    "mongo_creator_id" TEXT NOT NULL,
    "is_private" BOOLEAN NOT NULL DEFAULT false,
    "member_count" INTEGER NOT NULL DEFAULT 0,
    "last_message_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "categories" TEXT[] DEFAULT ARRAY[]::TEXT[],

    CONSTRAINT "channels_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "messages" (
    "id" UUID NOT NULL,
    "channel_id" UUID NOT NULL,
    "mongo_sender_id" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "content_type" TEXT NOT NULL DEFAULT 'text',
    "thread_id" UUID,
    "reply_count" INTEGER NOT NULL DEFAULT 0,
    "mongo_mentioned_user_ids" TEXT[],
    "is_edited" BOOLEAN NOT NULL DEFAULT false,
    "edited_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "parent_message_id" UUID,

    CONSTRAINT "messages_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reactions" (
    "id" UUID NOT NULL,
    "message_id" UUID NOT NULL,
    "channel_id" UUID NOT NULL,
    "mongo_user_id" TEXT NOT NULL,
    "emoji" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "reactions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "read_receipts" (
    "id" UUID NOT NULL,
    "message_id" UUID NOT NULL,
    "mongo_user_id" TEXT NOT NULL,
    "read_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "read_receipts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "channel_members_channel_id_mongo_member_id_key" ON "channel_members"("channel_id", "mongo_member_id");

-- CreateIndex
CREATE INDEX "channels_categories_idx" ON "channels" USING GIN ("categories");

-- CreateIndex
CREATE INDEX "messages_parent_message_id_idx" ON "messages"("parent_message_id");

-- CreateIndex
CREATE UNIQUE INDEX "reactions_message_id_mongo_user_id_emoji_key" ON "reactions"("message_id", "mongo_user_id", "emoji");

-- CreateIndex
CREATE UNIQUE INDEX "read_receipts_message_id_mongo_user_id_key" ON "read_receipts"("message_id", "mongo_user_id");

-- AddForeignKey
ALTER TABLE "attachments" ADD CONSTRAINT "attachments_channel_id_fkey" FOREIGN KEY ("channel_id") REFERENCES "channels"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "attachments" ADD CONSTRAINT "attachments_message_id_fkey" FOREIGN KEY ("message_id") REFERENCES "messages"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "channel_members" ADD CONSTRAINT "channel_members_channel_id_fkey" FOREIGN KEY ("channel_id") REFERENCES "channels"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "messages" ADD CONSTRAINT "messages_channel_id_fkey" FOREIGN KEY ("channel_id") REFERENCES "channels"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "messages" ADD CONSTRAINT "messages_parent_message_id_fkey" FOREIGN KEY ("parent_message_id") REFERENCES "messages"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reactions" ADD CONSTRAINT "reactions_channel_id_fkey" FOREIGN KEY ("channel_id") REFERENCES "channels"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reactions" ADD CONSTRAINT "reactions_message_id_fkey" FOREIGN KEY ("message_id") REFERENCES "messages"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "read_receipts" ADD CONSTRAINT "read_receipts_message_id_fkey" FOREIGN KEY ("message_id") REFERENCES "messages"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ============================================
-- Supabase Realtime Setup - API-Level Security
-- ============================================

-- This configuration DISABLES RLS and relies on API-level authentication
-- All security is handled through MongoDB auth and API endpoints
-- Supabase is only accessible via API keys (secure server-side)

-- 1. Create or use existing supabase_realtime publication
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    CREATE PUBLICATION supabase_realtime;
  END IF;
END $$;

-- 2. Enable Realtime for all communication tables
DO $$
BEGIN
  -- Add messages table to publication if not already added
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'messages'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE messages;
  END IF;

  -- Add channels table to publication if not already added
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'channels'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE channels;
  END IF;

  -- Add channel_members table to publication if not already added
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'channel_members'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE channel_members;
  END IF;

  -- Add reactions table to publication if not already added
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'reactions'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE reactions;
  END IF;

  -- Add attachments table to publication if not already added
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'attachments'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE attachments;
  END IF;

  -- Add read_receipts table to publication if not already added
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'read_receipts'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE read_receipts;
  END IF;
END $$;

-- 3. DISABLE Row Level Security (RLS) on communication tables for real-time
-- Security is handled through API authentication, not database-level
DO $$
DECLARE
  table_name text;
BEGIN
  FOR table_name IN
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public'
    AND tablename IN ('messages', 'channels', 'channel_members', 'reactions', 'attachments', 'read_receipts')
  LOOP
    EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY;', table_name);
  END LOOP;
END $$;
