import { relations } from 'drizzle-orm';
import { boolean, integer, pgTable, serial, text, timestamp } from 'drizzle-orm/pg-core';

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

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  profiles: many(profiles),
}));

export const profilesRelations = relations(profiles, ({ one }) => ({
  user: one(users, {
    fields: [profiles.userId],
    references: [users.id],
  }),
}));
