import "dotenv/config";
import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import cors from "cors";

// App and Port
const PORT = process.env.PORT || 3000;
const app = express();

// Use middleware
app.use(cors());
app.use(express.json());

// Connect to the database (pool)
const pool = mysql.createPool({
	host: process.env.DB_HOST,
	user: process.env.DB_USER,
	password: process.env.DB_PASS,
	database: process.env.DB_NAME,
	port: process.env.DB_PORT,
});

/* ----------------
   Helper functions
   ---------------- */

// SQL query with parameters that returns the result
async function query(sql, params) {
	const [results] = await pool.execute(sql, params);
	return results;
}

// Encrypts and returns the password
async function encryptPassword(password) {
	const saltRounds = 10;
	const encryptedPassword = await bcrypt.hash(password, saltRounds);
	return encryptedPassword;
}

// Generate otp
async function generateOtp() {
	const otp = Math.floor(100000 + Math.random() * 900000);
	return otp.toString();
}

// Clear sessions after 10 minutes
async function clearSessions() {
	const tenMinutes = 10 * 60 * 1000;
	const cutOff = new Date(new Date().getTime() - tenMinutes);
	try {
		const clear = await query("DELETE FROM sessions WHERE login_timestamp < ?", [cutOff]);
		console.log(`Cleared sessions: ${clear.affectedRows}`);
	} catch (error) {
		console.error("Error while clearing sessions:", error.message);
	} finally {
		setTimeout(clearSessions, tenMinutes);
	}
}

clearSessions();

/* ---------------
	Endpoints and
	CRUD functions
   --------------- */

// CREATE user (INSERT) - Create new user
app.post("/users", async (req, res) => {
	// Retrive username and password from the request body
	const { username, password } = req.body;

	try {
		// Encrypt the password
		const encryptedPassword = await encryptPassword(password);

		// INSERT user INTO users
		const result = await query("INSERT INTO users (username, password) VALUES ( ?, ? )", [username, encryptedPassword]);

		console.log("User created:", username);

		const [user] = await query("SELECT * FROM users WHERE username = ?", [username]);

		// INSERT user INTO accounts - Create account for user
		const zeroBalance = await query("INSERT INTO accounts (user_id, balance) VALUES ( ?, ? )", [user.id, 0]);

		res.status(201).json({ message: "User created" });
	} catch (error) {
		console.error("Error creating user:", error.message);
		res.status(500).json({ message: "Failed to create user" });
	}
});

// READ user (SELECT) - Login
app.post("/login", async (req, res) => {
	// Retrieve username and password from the request body
	const { username, password } = req.body;

	try {
		// SELECT user FROM users
		const [user] = await query("SELECT * FROM users WHERE username = ?", [username]);

		if (!user) {
			console.log("Login failed: Username not found.");
			return res.status(401).json({ message: "Login failed." });
		}

		// Compare password with the encrypted password in the database
		const passwordMatch = await bcrypt.compare(password, user.password);

		if (passwordMatch) {
			// Check for an existing user session
			const [existingSession] = await query("SELECT * FROM sessions WHERE user_id = ?", [user.id]);

			if (existingSession) {
				// Delete the existing session if it exists
				await query("DELETE FROM sessions WHERE user_id = ?", [user.id]);
				console.log("Deleted existing session for user:", username);
			}

			const otp = await generateOtp();
			console.log(otp);

			// Add the new session
			const result = await query("INSERT INTO sessions ( user_id, otp ) VALUES ( ?, ? )", [user.id, otp]);
			console.log("Login successful:", username);
			res.status(200).json({ otp: otp });
		} else {
			console.log("Login failed: Incorrect password.");
			return res.status(401).json({ message: "Login failed." });
		}
	} catch (error) {
		console.error("Error during login:", error);
		return res.status(500).json({ message: "An error occurred during login." });
	}
});

// UPDATE password (UPDATE) - New password
app.put("/update-password", async (req, res) => {
	// Retrieve username, old password and new password from the request body
	const { username, password, newPassword } = req.body;

	// SELECT user FROM users
	const [user] = await query("SELECT * FROM users WHERE username = ?", [username]);

	if (!user) {
		console.log("User not found or already deleted:", username);
		return res.status(404).json({ message: "User not found." });
	}

	// Compare the old password with the encrypted password in the database
	const passwordMatch = await bcrypt.compare(password, user.password);

	if (!passwordMatch) {
		return res.status(401).json({ message: "Invalid password" });
	}

	// Encrypt the new password
	const encryptedPassword = await encryptPassword(newPassword);

	try {
		// UPDATE user and SET new password in users
		const result = await query("UPDATE users SET password = ? WHERE id = ?", [encryptedPassword, user.id]);
		res.status(200).json({ message: "Password updated" });
	} catch (error) {
		console.error("Error updating user password:", error.message);
		res.status(500).json({ message: "Failed to update password" });
	}
});

// DELETE user (DELETE) - Delete user
app.delete("/delete-user", async (req, res) => {
	// Retrieve username from the request body
	const { username, password, otp } = req.body;

	// SELECT user FROM users
	const [user] = await query("SELECT * FROM users WHERE username = ?", [username]);

	if (!user) {
		console.log("User not found or already deleted:", username);
		return res.status(404).json({ message: "User not found" });
	}

	// If user exists, compare password with the encrypted password in the database
	const passwordMatch = await bcrypt.compare(password, user.password);

	if (!passwordMatch) {
		return res.status(401).json({ message: "Invalid password" });
	}

	// DELETE the current session
	const endSession = await query("DELETE FROM sessions WHERE user_id = ? AND otp = ?", [user.id, otp]);

	try {
		// DELETE user FROM users
		const result = await query("DELETE FROM users WHERE username = ?", [username]);
		res.status(200).json({ message: "User deleted" });
	} catch (error) {
		console.error("Error deleting user:", error.message);
		res.status(500).json({ message: "Failed to delete user" });
	}
});

// Log out
app.delete("/logout", async (req, res) => {
	// Retrieve username from the request body
	const { username, otp } = req.body;
	console.log(otp);
	// SELECT user FROM users
	const [user] = await query("SELECT * FROM users WHERE username = ?", [username]);

	if (!user) {
		console.log("User not found or already logged out:", username);
		return res.status(404).json({ message: "User not found or already logged out" });
	}

	try {
		// DELETE user FROM sessions
		const result = await query("DELETE FROM sessions WHERE user_id = ? AND otp = ?", [user.id, otp]);
		res.status(200).json({ message: "Logout successful" });
	} catch (error) {
		console.error("Error during user logout:", error.message);
		res.status(500).json({ message: "Failed to log out" });
	}
});

// Get account balance
app.post("/me/account", async (req, res) => {
	// Retrieve username and otp from the request body
	const { username, otp } = req.body;
	// SELECT user FROM users
	const [user] = await query("SELECT * FROM users WHERE username = ?", [username]);

	if (!user) {
		console.log("User not found or already logged out:", username);
		return res.status(404).json({ message: "User not found or already logged out" });
	}
	// SELECT all FROM sessions where user_id and otp match
	const validSession = await query("SELECT * FROM sessions WHERE user_id = ? AND otp = ?", [user.id, otp]);
	if (!validSession) {
		console.log("User not found or is logged out:", username);
		return res.status(404).json({ message: "Failed to get balance" });
	}

	// SELECT balance FROM the users account
	try {
		const result = await query("SELECT balance FROM accounts WHERE user_id = ?", [user.id]);
		const balance = result[0].balance;
		console.log(balance);
		res.status(200).json({ balance: balance });
	} catch (error) {
		return res.status(404).json({ message: "Failed to get balance" });
	}
});

app.post("/me/account/transaction/deposit", async (req, res) => {
	// Retrieve username and otp from the request body
	const { username, otp, amount } = req.body;
	// SELECT user FROM users
	const [user] = await query("SELECT * FROM users WHERE username = ?", [username]);

	if (!user) {
		console.log("User not found or already logged out:", username);
		return res.status(404).json({ message: "User not found or already logged out" });
	}
	// SELECT all FROM sessions where user_id and otp match
	const validSessions = await query("SELECT * FROM sessions WHERE user_id = ? AND otp = ?", [user.id, otp]);
	if (validSessions.length === 0) {
		console.log("Invalid session or OTP");
		return res.status(404).json({ message: "Invalid session or OTP" });
	}
	// SELECT balance FROM the users account and update balance
	try {
		const result = await query("SELECT balance FROM accounts WHERE user_id = ?", [user.id]);
		const balance = parseFloat(result[0].balance);
		console.log("Balance before deposit:", balance);
		const newBalance = balance + parseFloat(amount);
		await query("UPDATE accounts SET balance = ? WHERE user_id = ?", [newBalance, user.id]);

		// Return the updated balance
		res.status(200).json({ balance: newBalance });
	} catch (error) {
		console.error("Error updating balance:", error);
		return res.status(500).json({ message: "Failed to update balance" });
	}
});

app.post("/me/account/transaction/withdraw", async (req, res) => {
	// Retrieve username and otp from the request body
	const { username, otp, amount } = req.body;
	// SELECT user FROM users
	const [user] = await query("SELECT * FROM users WHERE username = ?", [username]);

	if (!user) {
		console.log("User not found or already logged out:", username);
		return res.status(404).json({ message: "User not found or already logged out" });
	}
	// SELECT all FROM sessions where user_id and otp match
	const validSessions = await query("SELECT * FROM sessions WHERE user_id = ? AND otp = ?", [user.id, otp]);
	if (validSessions.length === 0) {
		console.log("Invalid session or OTP");
		return res.status(404).json({ message: "Invalid session or OTP" });
	}
	// SELECT balance FROM the users account and update balance
	try {
		const result = await query("SELECT balance FROM accounts WHERE user_id = ?", [user.id]);
		const balance = parseFloat(result[0].balance);
		console.log("Balance before withdraw:", balance);
		const newBalance = balance - parseFloat(amount);
		await query("UPDATE accounts SET balance = ? WHERE user_id = ?", [newBalance, user.id]);

		// Return the updated balance
		res.status(200).json({ balance: newBalance });
	} catch (error) {
		console.error("Error updating balance:", error);
		return res.status(500).json({ message: "Failed to update balance" });
	}
});

/* ------------
   Start server
   ------------ */

// Listen to PORT
app.listen(PORT, () => {
	console.log("Server started on port: ", PORT);
});
