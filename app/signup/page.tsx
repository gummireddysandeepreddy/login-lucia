import Link from "next/link";

import { db } from "@/lib/db";
import { hash } from "@node-rs/argon2";
import { cookies } from "next/headers";
import { lucia, validateRequest } from "@/lib/auth";
import { redirect } from "next/navigation";
import { Form } from "@/lib/form";
import { generateId } from "lucia";
import { SqliteError } from "better-sqlite3";

import type { ActionResult } from "@/lib/form";

export default async function Page() {
	const { user } = await validateRequest();
	if (user) {
		return redirect("/");
	}
	return (
		<>
		<div className="h-full flex justify-center items-center">
			<div>
				<h1>Create an account</h1>
			</div>
			<div>
				<Form action={signup}>
					<label htmlFor="username">Username</label>
					<input name="username" id="username" />
					<br />
					<label htmlFor="password">Password</label>
					<input type="password" name="password" id="password" />
					<br />
					<button>Continue</button>
				</Form>
			</div>
			<div>
				<Link href="/login">Sign in</Link>
			</div>
		</div>
		</>
	);
}

async function signup(_: any, formData: FormData): Promise<ActionResult> {
	"use server";
	const username = formData.get("username");
	// username must be between 4 ~ 31 characters, and only consists of lowercase letters, 0-9, -, and _
	// keep in mind some database (e.g. mysql) are case insensitive
	if (
		typeof username !== "string" ||
		username.length < 3 ||
		username.length > 31 ||
		/^[a-z0-9_-]+$/.test(username)
	) {
		return {
			error: "Invalid username"
		};
	}
	const password = formData.get("password");
	if (typeof password !== "string" || password.length < 6 || password.length > 255) {
		return {
			error: "Invalid password"
		};
	}

	const passwordHash = await hash(password, {
		// recommended minimum parameters
		memoryCost: 19456,
		timeCost: 2,
		outputLen: 32,
		parallelism: 1
	});
	const userId = generateId(15);

	try {
		await db.execute({
			sql : "INSERT INTO user (id, username, password_hash) VALUES(?, ?, ?)",
			args : [userId,username,passwordHash],
		}).catch((e) => {
			return {
				error: e
			};
		});

		const session = await lucia.createSession(userId, {});
		const sessionCookie = lucia.createSessionCookie(session.id);
		cookies().set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
	} catch (e) {
		if (e instanceof SqliteError && e.code === "SQLITE_CONSTRAINT_UNIQUE") {
			return {
				error: "Username already used"
			};
		}
		return {
			error: "An unknown error occurred"
		};
	}
	return redirect("/");
}
