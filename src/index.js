import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { hostname } from "node:os";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";

import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";
import {
	getOrCreateUser,
	getUserProfiles,
	createProfile,
	updateProfile,
	deleteProfile,
	signUpUser,
	loginUser,
	verifySessionToken,
	getUserById,
	searchUsers,
	addFriend,
	removeFriend,
	getFriendsList,
	getDirectMessages,
	sendDirectMessage,
	getPublicMessages,
	sendPublicMessage
} from "./db/users.ts";
import { verifyAuth } from "./middleware/auth.ts";

const publicPath = fileURLToPath(new URL("../public/", import.meta.url));

// Wisp Configuration: Refer to the documentation at https://www.npmjs.com/package/@mercuryworkshop/wisp-js

logging.set_level(logging.NONE);
Object.assign(wisp.options, {
	allow_udp_streams: false,
	hostname_blacklist: [/example\.com/],
	dns_servers: ["1.1.1.3", "1.0.0.3"],
});

const fastify = Fastify({
	serverFactory: (handler) => {
		return createServer()
			.on("request", (req, res) => {
				res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
				res.setHeader("Cross-Origin-Embedder-Policy", "credentialless");
				res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
				handler(req, res);
			})
			.on("upgrade", (req, socket, head) => {
				if (req.url.endsWith("/wisp/")) wisp.routeRequest(req, socket, head);
				else socket.end();
			});
	},
});

fastify.register(fastifyStatic, {
	root: publicPath,
	decorateReply: true,
});

fastify.register(fastifyStatic, {
	root: scramjetPath,
	prefix: "/scram/",
	decorateReply: false,
});

fastify.register(fastifyStatic, {
	root: libcurlPath,
	prefix: "/libcurl/",
	decorateReply: false,
});

fastify.register(fastifyStatic, {
	root: baremuxPath,
	prefix: "/baremux/",
	decorateReply: false,
});

let ipCache = { value: null, at: 0 };
async function serverIp() {
	if (ipCache.value && Date.now() - ipCache.at < 10 * 60 * 1000) return ipCache.value;
	try {
		const r = await fetch("https://api.ipify.org?format=json", {
			signal: AbortSignal.timeout(4000),
		});
		const j = await r.json();
		if (j && typeof j.ip === "string") {
			ipCache = { value: j.ip, at: Date.now() };
			return j.ip;
		}
	} catch (e) {}
	return ipCache.value;
}

fastify.get("/api/info", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	return {
		time: Date.now(),
		uptime: Math.round(process.uptime()),
		ip: await serverIp(),
	};
});

async function resolveUserId(req) {
	const authHeader = req.headers.authorization;
	if (authHeader) {
		const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
		const session = verifySessionToken(token);
		if (session && session.userId) return session.userId;

		const verified = await verifyAuth(authHeader);
		if (verified && verified.dbUserId) return verified.dbUserId;
	}
	const clientId = (req.headers["x-client-id"] || "default-voyager").toString().slice(0, 64);
	const u = await getOrCreateUser(clientId, `${clientId}@scramjet.local`);
	return u.id;
}

// Authentication API (Sign Up, Login, Me)
fastify.post("/api/auth/signup", async (req, reply) => {
	try {
		const body = req.body || {};
		const username = (body.username || "").trim();
		const password = body.password || "";
		const email = (body.email || "").trim();

		if (!username || !password) {
			reply.code(400);
			return { success: false, error: "Username and password are required" };
		}

		const result = await signUpUser(username, password, email);
		return { success: true, ...result };
	} catch (err) {
		req.log.error(err);
		reply.code(400);
		return { success: false, error: err.message || "Failed to create account" };
	}
});

fastify.post("/api/auth/login", async (req, reply) => {
	try {
		const body = req.body || {};
		const username = (body.username || "").trim();
		const password = body.password || "";

		if (!username || !password) {
			reply.code(400);
			return { success: false, error: "Username and password are required" };
		}

		const result = await loginUser(username, password);
		return { success: true, ...result };
	} catch (err) {
		req.log.error(err);
		reply.code(401);
		return { success: false, error: err.message || "Invalid credentials" };
	}
});

fastify.get("/api/auth/me", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const authHeader = req.headers.authorization;
		if (authHeader) {
			const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
			const session = verifySessionToken(token);
			if (session) {
				const user = await getUserById(session.userId);
				if (user) {
					const profiles = await getUserProfiles(user.id);
					return {
						success: true,
						authenticated: true,
						user: { id: user.id, username: user.username, email: user.email },
						profiles,
						activeProfile: profiles.find(p => p.isDefault) || profiles[0]
					};
				}
			}
		}
		return { success: true, authenticated: false };
	} catch (err) {
		req.log.error(err);
		return { success: false, authenticated: false };
	}
});

// Cloud SQL Profiles API
fastify.get("/api/profiles", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await resolveUserId(req);
		let list = await getUserProfiles(userId);
		if (list.length === 0) {
			const initial = await createProfile(userId, {
				name: "Voyager",
				avatar: "astronaut",
				themeColor: "#5aa2ff",
				bio: "Curator of the cosmos",
				shortcuts: JSON.stringify([
					{ name: "TikTok", url: "https://www.tiktok.com" },
					{ name: "Instagram", url: "https://www.instagram.com" },
					{ name: "GeForce NOW", url: "https://play.geforcenow.com" },
					{ name: "Cork7", url: "https://cork7.com" }
				]),
				preferences: JSON.stringify({
					searchEngine: "https://www.google.com/search?q=",
					stars: true,
					shoot: true,
					bg: "stars"
				}),
				isDefault: true
			});
			list = [initial];
		}
		return { success: true, profiles: list };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Database operation failed" };
	}
});

fastify.post("/api/profiles", async (req, reply) => {
	try {
		const userId = await resolveUserId(req);
		const body = req.body || {};
		if (!body.name || !body.name.trim()) {
			reply.code(400);
			return { success: false, error: "Profile name is required" };
		}
		const profile = await createProfile(userId, {
			name: body.name.trim(),
			avatar: body.avatar || "astronaut",
			themeColor: body.themeColor || "#5aa2ff",
			bio: body.bio || "",
			shortcuts: body.shortcuts,
			preferences: body.preferences,
			isDefault: !!body.isDefault
		});
		return { success: true, profile };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Failed to create profile" };
	}
});

fastify.put("/api/profiles/:id", async (req, reply) => {
	try {
		const userId = await resolveUserId(req);
		const profileId = parseInt(req.params.id, 10);
		if (isNaN(profileId)) {
			reply.code(400);
			return { success: false, error: "Invalid profile ID" };
		}
		const body = req.body || {};
		const updated = await updateProfile(profileId, userId, body);
		if (!updated) {
			reply.code(404);
			return { success: false, error: "Profile not found" };
		}
		return { success: true, profile: updated };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Failed to update profile" };
	}
});

fastify.delete("/api/profiles/:id", async (req, reply) => {
	try {
		const userId = await resolveUserId(req);
		const profileId = parseInt(req.params.id, 10);
		if (isNaN(profileId)) {
			reply.code(400);
			return { success: false, error: "Invalid profile ID" };
		}
		const deleted = await deleteProfile(profileId, userId);
		if (!deleted) {
			reply.code(404);
			return { success: false, error: "Profile not found" };
		}
		return { success: true, deletedId: profileId };
	} catch (err) {
		req.log.error(err);
		reply.code(500);
		return { success: false, error: "Failed to delete profile" };
	}
});

// Helper for authenticated user in chat and friends
async function getAuthUserId(req, reply) {
	const authHeader = req.headers.authorization;
	if (!authHeader) {
		reply.code(401);
		throw new Error("Authentication required. Please sign in.");
	}
	const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
	const session = verifySessionToken(token);
	if (!session || !session.userId) {
		reply.code(401);
		throw new Error("Session expired or invalid. Please sign in again.");
	}
	return session.userId;
}

// Friends & Chat API Routes
fastify.get("/api/users/search", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const q = (req.query?.q || "").toString();
		const results = await searchUsers(q, userId);
		return { success: true, users: results };
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

fastify.get("/api/friends", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const list = await getFriendsList(userId);
		return { success: true, friends: list };
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

fastify.post("/api/friends", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const body = req.body || {};
		const username = (body.username || "").trim();
		if (!username) {
			reply.code(400);
			return { success: false, error: "Please enter a username to add" };
		}
		const friend = await addFriend(userId, username);
		return { success: true, friend };
	} catch (err) {
		reply.code(err.message.includes("not found") ? 404 : 400);
		return { success: false, error: err.message };
	}
});

fastify.delete("/api/friends/:friendId", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const friendId = parseInt(req.params.friendId, 10);
		if (isNaN(friendId)) {
			reply.code(400);
			return { success: false, error: "Invalid friend ID" };
		}
		await removeFriend(userId, friendId);
		return { success: true };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.get("/api/messages/:friendId", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const userId = await getAuthUserId(req, reply);
		const friendId = parseInt(req.params.friendId, 10);
		if (isNaN(friendId)) {
			reply.code(400);
			return { success: false, error: "Invalid friend ID" };
		}
		const messages = await getDirectMessages(userId, friendId);
		return { success: true, messages };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.post("/api/messages/:friendId", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const friendId = parseInt(req.params.friendId, 10);
		const body = req.body || {};
		const content = (body.content || "").trim();
		if (isNaN(friendId)) {
			reply.code(400);
			return { success: false, error: "Invalid friend ID" };
		}
		if (!content) {
			reply.code(400);
			return { success: false, error: "Message cannot be empty" };
		}
		const message = await sendDirectMessage(userId, friendId, content);
		return { success: true, message };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

// Public Channels API Routes (chat-1, chat-2, announcements)
fastify.get("/api/public-messages/:channel", async (req, reply) => {
	reply.header("Cache-Control", "no-store");
	try {
		const channel = (req.params.channel || "chat-1").toString();
		const messages = await getPublicMessages(channel);
		return { success: true, channel, messages };
	} catch (err) {
		reply.code(400);
		return { success: false, error: err.message };
	}
});

fastify.post("/api/public-messages/:channel", async (req, reply) => {
	try {
		const userId = await getAuthUserId(req, reply);
		const channel = (req.params.channel || "chat-1").toString();
		const body = req.body || {};
		const content = (body.content || "").trim();
		if (!content) {
			reply.code(400);
			return { success: false, error: "Message cannot be empty" };
		}
		const message = await sendPublicMessage(channel, userId, content);
		return { success: true, message };
	} catch (err) {
		reply.code(err.message.includes("Authentication") ? 401 : 400);
		return { success: false, error: err.message };
	}
});

fastify.setNotFoundHandler((res, reply) => {
	return reply.code(404).type("text/html").sendFile("404.html");
});

fastify.server.on("listening", () => {
	const address = fastify.server.address();
	console.log(`Scramjet proxy listening on http://0.0.0.0:${address.port}`);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server");
	fastify.close();
	process.exit(0);
}

let port = parseInt(process.env.PORT || "");
const portArgIdx = process.argv.indexOf("--port");
if (portArgIdx !== -1 && process.argv[portArgIdx + 1]) {
  const parsed = parseInt(process.argv[portArgIdx + 1], 10);
  if (!isNaN(parsed)) port = parsed;
}
if (isNaN(port)) port = 3000;

fastify.listen({
	port: port,
	host: "0.0.0.0",
});
