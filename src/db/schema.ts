import { relations } from 'drizzle-orm';
import { boolean, integer, pgTable, serial, text, timestamp, uniqueIndex } from 'drizzle-orm/pg-core';

// Define the 'users' table linking to user auth or guest UID
export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  uid: text('uid').notNull().unique(), // Auth UID or client identifier
  username: text('username'),
  passwordHash: text('password_hash'),
  email: text('email').notNull(),
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

