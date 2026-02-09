-- AlterTable
ALTER TABLE "channel_members" ADD COLUMN     "added_by" TEXT,
ADD COLUMN     "added_via" TEXT,
ADD COLUMN     "is_pinned" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "pinned_at" TIMESTAMPTZ(6);

-- AlterTable
ALTER TABLE "channels" ADD COLUMN     "admin_only_add" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "admin_only_post" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "allow_external_members" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "archived_at" TIMESTAMPTZ(6),
ADD COLUMN     "archived_by" TEXT,
ADD COLUMN     "auto_sync_enabled" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "is_archived" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "messages" ADD COLUMN     "hidden_by_users" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "is_trashed" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "original_content" TEXT,
ADD COLUMN     "sender_avatar" TEXT,
ADD COLUMN     "sender_email" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "sender_name" TEXT NOT NULL DEFAULT 'Unknown User',
ADD COLUMN     "sender_role" TEXT NOT NULL DEFAULT 'User',
ADD COLUMN     "trash_reason" TEXT,
ADD COLUMN     "trashed_at" TIMESTAMPTZ(6),
ADD COLUMN     "trashed_by" TEXT;

-- AlterTable
ALTER TABLE "reactions" ADD COLUMN     "user_name" TEXT NOT NULL DEFAULT 'Unknown';

-- CreateTable
CREATE TABLE "PinnedUser" (
    "id" TEXT NOT NULL,
    "pinner_id" TEXT NOT NULL,
    "pinned_user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PinnedUser_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PinnedUser_pinner_id_idx" ON "PinnedUser"("pinner_id");

-- CreateIndex
CREATE UNIQUE INDEX "PinnedUser_pinner_id_pinned_user_id_key" ON "PinnedUser"("pinner_id", "pinned_user_id");

-- CreateIndex
CREATE INDEX "channel_members_mongo_member_id_idx" ON "channel_members"("mongo_member_id");

-- CreateIndex
CREATE INDEX "channel_members_channel_id_role_idx" ON "channel_members"("channel_id", "role");

-- CreateIndex
CREATE INDEX "channel_members_mongo_member_id_is_pinned_idx" ON "channel_members"("mongo_member_id", "is_pinned");

-- CreateIndex
CREATE INDEX "channels_is_archived_idx" ON "channels"("is_archived");

-- CreateIndex
CREATE INDEX "channels_mongo_department_id_idx" ON "channels"("mongo_department_id");

-- CreateIndex
CREATE INDEX "channels_mongo_project_id_idx" ON "channels"("mongo_project_id");

-- CreateIndex
CREATE INDEX "channels_auto_sync_enabled_is_archived_idx" ON "channels"("auto_sync_enabled", "is_archived");

-- CreateIndex
CREATE INDEX "messages_channel_id_is_trashed_created_at_idx" ON "messages"("channel_id", "is_trashed", "created_at" DESC);

-- CreateIndex
CREATE INDEX "messages_mongo_sender_id_is_trashed_idx" ON "messages"("mongo_sender_id", "is_trashed");

-- CreateIndex
CREATE INDEX "messages_is_trashed_trashed_at_idx" ON "messages"("is_trashed", "trashed_at");
