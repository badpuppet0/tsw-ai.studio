import { relations } from 'drizzle-orm';
import { boolean, integer, pgTable, primaryKey, serial, text, timestamp, uniqueIndex } from 'drizzle-orm/pg-core';

// Define the 'users' table linking to user auth or guest UID
export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  uid: text('uid').notNull().unique(), // Auth UID or client identifier
  username: text('username'),
  passwordHash: text('password_hash'),
  email: text('email').notNull(),
  role: text('role').default('TSW User').notNull(),
  createdAt: timestamp('created_at').defaultNow(),
});

// Define the 'profiles' table for user profiles
export const profiles = pgTable('profiles', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  avatar: text('avatar').default('astronaut').notNull(),
  themeColor: text('theme_color').default('#5aa2ff').notNull(),
  bio: text('bio').default('').notNull(),
  shortcuts: text('shortcuts').default('[]').notNull(),
  preferences: text('preferences').default('{}').notNull(),
  isDefault: boolean('is_default').default(false).notNull(),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Define the 'friends' table
export const friends = pgTable('friends', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  friendId: integer('friend_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  status: text('status').default('accepted').notNull(),
  createdAt: timestamp('created_at').defaultNow(),
}, (t) => ({
  userFriendUnique: uniqueIndex('idx_friends_user_friend').on(t.userId, t.friendId),
}));

// Define the 'messages' table for private direct messages
export const messages = pgTable('messages', {
  id: serial('id').primaryKey(),
  senderId: integer('sender_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  receiverId: integer('receiver_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  content: text('content').notNull(),
  isRead: boolean('is_read').default(false).notNull(),
  createdAt: timestamp('created_at').defaultNow(),
});

// Define the 'public_messages' table for public channels (chat-1, chat-2, announcements)
export const publicMessages = pgTable('public_messages', {
  id: serial('id').primaryKey(),
  channel: text('channel').notNull(), // 'chat-1' | 'chat-2' | 'announcements'
  userId: integer('user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  content: text('content').notNull(),
  createdAt: timestamp('created_at').defaultNow(),
});

// Define the 'chat_presence' table
export const chatPresence = pgTable('chat_presence', {
  userId: integer('user_id').references(() => users.id, { onDelete: 'cascade' }).primaryKey(),
  lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).defaultNow().notNull(),
});

// Define the 'chat_typing' table
export const chatTyping = pgTable('chat_typing', {
  userId: integer('user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  chatType: text('chat_type').notNull(),
  contextId: text('context_id').notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => ({
  pk: primaryKey({ columns: [t.userId, t.chatType, t.contextId] }),
}));

// Define the 'user_alerts' table for owner direct broadcasts
export const userAlerts = pgTable('user_alerts', {
  id: serial('id').primaryKey(),
  targetUserId: integer('target_user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  senderId: integer('sender_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  message: text('message').notNull(),
  delivered: boolean('delivered').default(false).notNull(),
  read: boolean('read').default(false).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// Define the 'chat_message_reactions' table
export const chatMessageReactions = pgTable('chat_message_reactions', {
  id: serial('id').primaryKey(),
  messageType: text('message_type').notNull(),
  messageId: integer('message_id').notNull(),
  userId: integer('user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  emoji: text('emoji').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// Define the 'chat_reports' table
export const chatReports = pgTable('chat_reports', {
  id: serial('id').primaryKey(),
  reporterId: integer('reporter_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  reportedUserId: integer('reported_user_id').references(() => users.id, { onDelete: 'set null' }),
  messageType: text('message_type'),
  messageId: integer('message_id'),
  reason: text('reason').notNull(),
  details: text('details').default(''),
  status: text('status').default('open').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// Define the 'chat_moderation_logs' table
export const chatModerationLogs = pgTable('chat_moderation_logs', {
  id: serial('id').primaryKey(),
  actorId: integer('actor_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  targetUserId: integer('target_user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
  action: text('action').notNull(),
  reason: text('reason').default(''),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  profiles: many(profiles),
  friends: many(friends, { relationName: 'userFriends' }),
  sentMessages: many(messages, { relationName: 'sentMessages' }),
  receivedMessages: many(messages, { relationName: 'receivedMessages' }),
  publicMessages: many(publicMessages),
}));

export const profilesRelations = relations(profiles, ({ one }) => ({
  user: one(users, {
    fields: [profiles.userId],
    references: [users.id],
  }),
}));

export const publicMessagesRelations = relations(publicMessages, ({ one }) => ({
  user: one(users, {
    fields: [publicMessages.userId],
    references: [users.id],
  }),
}));

