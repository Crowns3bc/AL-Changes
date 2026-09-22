const crypto = require("node:crypto");
const net = require("node:net");
const { create_steam_verifier } = require("./steam_signup");

const LIFETIME = 5 * 60 * 1000;
const PAGE_SIZE = 20;
const secret = () => crypto.randomBytes(32).toString("hex");
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const valid_secret = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

// All authorization lives in shared storage. A browser choice never becomes a user query.
function create_steam_signin({ client, collection, users, get_user, hash_password, get_new_auth, set_link, render, finish_login, preference, auth_cookie, local_origin, request, now = Date.now }) {
	const verifier = create_steam_verifier({ local_origin, request, now });
	const cookie_name = local_origin ? "al_steam_signin_local" : "__Host-al_steam_signin";
	const cookie_options = { httpOnly: true, secure: !local_origin, sameSite: "lax", path: "/", maxAge: LIFETIME };
	function cookie(req) {
		const raw = req.get("cookie") || "";
		if (raw.split(";").filter((part) => part.trim().split("=")[0] === cookie_name).length > 1) throw new Error("failed");
		const value = req.cookies && req.cookies[cookie_name];
		return valid_secret(value) ? value : null;
	}
	const flow_id = (token) => "flow:" + hash(token);
	const csrf = (token) => hash("csrf\0" + token);
	const password_revision = (user) => hash(user.password + "\0" + (user.info.salt || "5"));
	function current_auth(req, user) {
		const raw = req.get("cookie") || "";
		if (raw.split(";").filter((part) => part.trim().split("=")[0] === auth_cookie).length > 1) throw new Error("failed");
		const value = req.cookies && req.cookies[auth_cookie];
		if (typeof value !== "string") throw new Error("failed");
		const parts = value.replace(/"/g, "").split("-");
		if (parts.length !== 2 || parts[0].replace(/^US_/, "") !== user._id.replace(/^US_/, "") || !user.info.auths.includes(parts[1])) throw new Error("failed");
		return hash(parts[1]);
	}
	function eligible(user) {
		return user && !user.banned && !(user.server && now() - +new Date(user.last_online) < 900000 && now() - +new Date(user.info.last_auth) < 900000);
	}
	function linked(user, flow) {
		if (!user || user._id !== flow.owner || !eligible(user) || user.server || password_revision(user) !== flow.password_revision) throw new Error("failed");
		if (!user.info.auths.some((auth) => hash(auth) === flow.auth)) throw new Error("failed");
	}
	async function transaction(action) {
		const session = client.startSession();
		try {
			return await session.withTransaction(() => action(session), { readConcern: { level: "snapshot" }, writeConcern: { w: "majority" }, maxCommitTimeMS: 5000 });
		} finally {
			await session.endSession();
		}
	}
	function live(flow, req, purpose, stage) {
		if (!flow || flow.origin !== verifier.origin(req) || flow.purpose !== purpose || +flow.expires <= now() || (stage && flow.stage !== stage)) throw new Error("failed");
		return flow;
	}
	async function load(req, purpose, stage, session) {
		const token = cookie(req);
		if (!token) throw new Error("failed");
		return live(await collection.findOne({ _id: flow_id(token) }, { session }), req, purpose, stage);
	}
	async function limited(req, steamid) {
		// The nearest proxy must append/overwrite X-Forwarded-For. Never trust its leftmost client-supplied value.
		let ip = (req.socket && req.socket.remoteAddress) || "unknown";
		if (["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(ip)) {
			const forwarded = (req.get("x-forwarded-for") || "").split(",").pop().trim();
			if (net.isIP(forwarded)) ip = forwarded;
		}
		for (const [bucket, limit] of [["global", 4000], ["ip:" + ip, 120], ...(steamid ? [["steam:" + steamid, 40]] : [])]) {
			const window = Math.floor(now() / LIFETIME);
			const record = await collection.findOneAndUpdate(
				{ _id: "limit:" + hash(bucket) + ":" + window },
				{ $inc: { count: 1 }, $setOnInsert: { expires: new Date((window + 2) * LIFETIME) } },
				{ upsert: true, returnDocument: "after" },
			);
			if (record.count > limit) throw new Error("unavailable");
		}
	}
	async function invalidate(req, res) {
		const token = cookie(req);
		if (token) await collection.deleteOne({ _id: flow_id(token) });
		const { maxAge, ...clear } = cookie_options;
		res.clearCookie(cookie_name, clear);
	}
	function guard(purpose, action) {
		return async (req, res, next) => {
			res.set({
				"Cache-Control": "no-store",
				"Referrer-Policy": "strict-origin",
				"X-Frame-Options": "DENY",
				"X-Robots-Tag": "noindex",
				"Content-Security-Policy": "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; form-action 'self' https://steamcommunity.com; base-uri 'none'; frame-ancestors 'none'",
			});
			try {
				verifier.origin(req);
				if (req.originalUrl.length > 8192 || Number(req.get("content-length") || 0) > 4096) throw new Error("failed");
				if (req.method === "POST" && (req.get("origin") !== verifier.origin(req) || !cookie(req) || typeof req.body.state !== "string" || req.body.state !== csrf(cookie(req))))
					throw new Error("failed");
				const user = await get_user(req);
				if ((purpose === "signin" && user) || (purpose === "link" && !user)) {
					await invalidate(req, res);
					return res.redirect(303, "/");
				}
				if (user) current_auth(req, user);
				await limited(req);
				await action(req, res, user);
			} catch (error) {
				const failed = error.message === "failed" || error.code === 11000,
					wrong = error.message === "wrong_password";
				const reason = wrong ? "error.wrong_password" : failed ? "pages.steam_signup.failed" : "pages.steam_signup.unavailable";
				try {
					res.status(failed || wrong ? 400 : 503);
					await render(req, res, { view: "error", error: reason, link: purpose === "link" });
				} catch (_) {
					next(new Error("Steam sign-in unavailable"));
				}
			}
		};
	}
	async function page(req, res, purpose, user) {
		await invalidate(req, res);
		const token = secret();
		await collection.insertOne({ _id: flow_id(token), purpose, stage: "form", origin: verifier.origin(req), expires: new Date(now() + LIFETIME) });
		res.cookie(cookie_name, token, cookie_options);
		await render(req, res, { view: purpose === "link" ? "settings" : "start", state: csrf(token), enabled: !!(user && user.steam_login && user.steam_login.enabled) });
	}
	async function start(req, res, purpose, user) {
		let proof = {};
		if (purpose === "link") {
			if (typeof req.body.password !== "string" || !req.body.password.length || req.body.password.length > 1024 || hash_password(req.body.password, user.info.salt || "5") !== user.password)
				throw new Error("wrong_password");
			if (!eligible(user) || user.server) throw new Error("failed");
			proof = { owner: user._id, auth: current_auth(req, user), password_revision: password_revision(user) };
		}
		const state = secret();
		await transaction(async (session) => {
			const flow = await load(req, purpose, "form", session);
			Object.assign(flow, proof, { state, stage: "pending", expires: new Date(now() + LIFETIME) });
			await collection.replaceOne({ _id: flow._id }, flow, { session });
		});
		const address = verifier.origin(req) + "/steam-signin/" + (purpose === "link" ? "link/" : "") + "callback?state=" + state;
		res.cookie(cookie_name, cookie(req), cookie_options);
		res.redirect(303, verifier.start(address, verifier.origin(req)));
	}
	async function callback(req, res, purpose, user) {
		const flow = await load(req, purpose, "pending");
		if (new URL(req.originalUrl, flow.origin).searchParams.get("state") !== flow.state) throw new Error("failed");
		if (purpose === "link") {
			linked(user, flow);
			if (current_auth(req, user) !== flow.auth) throw new Error("failed");
		}
		const address = flow.origin + "/steam-signin/" + (purpose === "link" ? "link/" : "") + "callback?state=" + flow.state;
		const identity = await verifier.verify(req, address, LIFETIME);
		await limited(req, identity.steamid);
		const next_token = secret();
		await transaction(async (session) => {
			const current = await load(req, purpose, "pending", session);
			if (current.state !== flow.state) throw new Error("failed");
			await collection.insertOne({ _id: "nonce:" + hash(identity.nonce), expires: new Date(now() + LIFETIME + 60000) }, { session });
			await collection.deleteOne({ _id: current._id }, { session });
			Object.assign(current, { _id: flow_id(next_token), stage: "ready", steamid: identity.steamid, expires: new Date(now() + LIFETIME), choices: [] });
			await collection.insertOne(current, { session });
		});
		res.cookie(cookie_name, next_token, cookie_options);
		res.redirect(303, purpose === "link" ? "/steam-signin/link/confirm" : "/steam-signin/accounts");
	}
	async function accounts(req, res) {
		const result = await transaction(async (session) => {
			const flow = await load(req, "signin", "ready", session);
			if (req.method === "POST") {
				if (req.body.more !== "yes" || !flow.next) throw new Error("failed");
				flow.cursor = flow.next;
			}
			const query = { "steam_login.steamid": flow.steamid, "steam_login.enabled": true, banned: { $ne: true } };
			if (flow.cursor) query._id = { $gt: flow.cursor };
			const rows = await users
				.find(query, { session, projection: { _id: 1, name: 1, email: 1, "info.characters": 1, steam_login: 1, steam_auth_revision: 1 } })
				.sort({ _id: 1 })
				.limit(PAGE_SIZE + 1)
				.maxTimeMS(3000)
				.toArray();
			flow.next = rows.length > PAGE_SIZE ? rows[PAGE_SIZE - 1]._id : null;
			flow.choices = [];
			const listed = rows.slice(0, PAGE_SIZE).map((user) => {
				const handle = secret();
				flow.choices.push({ handle: hash(handle), id: user._id, version: user.steam_login.version, revision: user.steam_auth_revision || "" });
				const email = typeof user.email?.[0] === "string" ? user.email[0].split("@") : [];
				return {
					handle,
					name: String(user.name || "").slice(0, 80),
					email: email.length === 2 ? email[0].slice(0, 1) + "***@" + email[1].slice(0, 1) + "***" : "",
					characters: (user.info?.characters || [])
						.slice(0, 3)
						.map((c) => String(c.name || "").slice(0, 40))
						.join(", "),
				};
			});
			await collection.replaceOne({ _id: flow._id }, flow, { session });
			return { view: "accounts", accounts: listed, next: !!flow.next, digits: flow.steamid.slice(-4), state: csrf(cookie(req)) };
		});
		await render(req, res, result);
	}
	async function complete(req, res) {
		if (!valid_secret(req.body.account)) throw new Error("failed");
		const result = await transaction(async (session) => {
			const flow = await load(req, "signin", "ready", session);
			const selected = flow.choices.find((c) => c.handle === hash(req.body.account));
			if (!selected) throw new Error("failed");
			const user = await users.findOne({ _id: selected.id }, { session });
			if (
				!eligible(user) ||
				!user.steam_login?.enabled ||
				user.steam_login.steamid !== flow.steamid ||
				user.steam_login.version !== selected.version ||
				(user.steam_auth_revision || "") !== selected.revision
			)
				throw new Error("failed");
			Object.assign(user, preference(req, user));
			const auth = get_new_auth(user);
			user.info.steam_auths = [...(user.info.steam_auths || []), auth];
			await users.replaceOne({ _id: user._id }, user, { session });
			await collection.deleteOne({ _id: flow._id }, { session });
			return { user, auth };
		});
		await invalidate(req, res);
		await finish_login(req, res, result.user, result.auth);
		res.redirect(303, "/");
	}
	async function confirm(req, res, user) {
		const flow = await load(req, "link", "ready");
		linked(user, flow);
		if (current_auth(req, user) !== flow.auth) throw new Error("failed");
		await render(req, res, { view: "confirm", account: user.name, digits: flow.steamid.slice(-4), state: csrf(cookie(req)) });
	}
	async function change_link(req, res, existing, disable) {
		if (
			disable &&
			(typeof req.body.password !== "string" || !req.body.password.length || req.body.password.length > 1024 || hash_password(req.body.password, existing.info.salt || "5") !== existing.password)
		)
			throw new Error("wrong_password");
		const result = await transaction(async (session) => {
			const flow = await load(req, "link", disable ? "form" : "ready", session);
			const user = await users.findOne({ _id: existing._id }, { session });
			if (disable) {
				if (!eligible(user) || user.server || password_revision(user) !== password_revision(existing) || current_auth(req, user) !== current_auth(req, existing)) throw new Error("failed");
			} else {
				linked(user, flow);
				if (current_auth(req, user) !== flow.auth) throw new Error("failed");
			}
			set_link(user, disable ? null : flow.steamid, "password_openid");
			const auth = get_new_auth(user);
			await users.replaceOne({ _id: user._id }, user, { session });
			await collection.deleteOne({ _id: flow._id }, { session });
			return { user, auth };
		});
		await invalidate(req, res);
		await finish_login(req, res, result.user, result.auth);
		await render(req, res, { view: "done", disabled: disable });
	}
	return {
		invalidate,
		page: guard("signin", (req, res) => page(req, res, "signin")),
		start: guard("signin", (req, res) => start(req, res, "signin")),
		callback: guard("signin", (req, res) => callback(req, res, "signin")),
		accounts: guard("signin", accounts),
		complete: guard("signin", complete),
		cancel: guard("signin", async (req, res) => {
			await invalidate(req, res);
			res.redirect(303, "/");
		}),
		link_page: guard("link", (req, res, user) => page(req, res, "link", user)),
		link_start: guard("link", (req, res, user) => start(req, res, "link", user)),
		link_callback: guard("link", (req, res, user) => callback(req, res, "link", user)),
		link_confirm: guard("link", confirm),
		link_complete: guard("link", (req, res, user) => change_link(req, res, user, false)),
		link_disable: guard("link", (req, res, user) => change_link(req, res, user, true)),
	};
}

module.exports = { create_steam_signin };
