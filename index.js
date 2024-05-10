/** @format */

// @ts-nocheck
/** @format */

const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const User = require("./model/User");
const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const middleware = require("./middleware");

dotenv.config();
const app = express();
app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true }));
// Use express-session middleware
app.use(
	session({
		secret: process.env.JWT_SECRET, // Change to a random secret key
		resave: false,
		saveUninitialized: false,
	})
);
app.use(passport.session()); // Use passport.session() after express-session middleware

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
	await User.findById(id, function (err, user) {
		done(err, user);
	});
});

// DB Connection
mongoose
	.connect(process.env.MONGO_URL, {
		useNewUrlParser: true,
		useUnifiedTopology: true,
	})
	.then(() => {
		console.log("DB Connection Successful!");
	})
	.catch((err) => console.log(err));

// jwt authenticate
passport.use(
	new JwtStrategy(
		{
			jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
			secretOrKey: process.env.JWT_SECRET, // Your secret key
		},
		async (payload, done) => {
			console.log(payload);
			try {
				// Extract user ID from payload
				const userId = payload.id;

				// Find user by ID in database
				const user = await User.findById(userId);
				console.log(user);

				// If user not found, return false
				if (!user) {
					return done(null, false);
				}

				// If user found, return user
				return done(null, user);
			} catch (err) {
				console.log(err.message);
				return done(err, false);
			}
		}
	)
);

// Initialize Passport
app.use(passport.initialize());

// Middleware to authenticate requests using JWT
const authenticateJwt = passport.authenticate("jwt", { session: false });

// Google
passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.GOOGLE_CLIENT_ID,
			clientSecret: process.env.GOOGLE_CLIENT_SECRET,
			callbackURL: "/auth/google/callback",
		},
		async (accessToken, refreshToken, profile, done) => {
			try {
				let user = await User.findOne({ email: profile.emails[0].value });

				if (!user) {
					// Create new user if not exists
					user = new User({
						name: profile.displayName,
						email: profile.emails[0].value,
						password: "dummyPassword", // Dummy password as it's required in User schema
						// Other profile fields can be populated here
						// Other profile fields can be populated here
					});
					await user.save();
				}

				return done(null, user);
			} catch (err) {
				return done(err, false);
			}
		}
	)
);

// OAuth Google Login
app.get(
	"/auth/google",
	passport.authenticate("google", { scope: ["profile", "email"] })
);
app.get(
	"/auth/google/callback",
	passport.authenticate("google", { failureRedirect: "/login" }),
	(req, res) => {
		// Successful authentication, redirect or respond with token
		const token = jwt.sign({ id: req.user.id }, process.env.JWT_SECRET, {
			expiresIn: "1h",
		});
		res.json({ token });
	}
);

app.post("/register", async (req, res) => {
	try {
		console.log(JSON.stringify(req.body));
		const { name, email, password, phoneNumber, role } = req.body;
		// Check if user already exists
		let user = await User.findOne({ email });
		if (user) {
			return res.status(400).json({ message: "User already exists" });
		}

		// Create new user
		user = new User({
			name,
			email,
			password,
			role,
			phoneNumber,
		});

		// Hash password
		const salt = await bcrypt.genSalt(10);
		user.password = await bcrypt.hash(password, salt);

		await user.save();
		return res.status(201).json({ message: "User registered successfully" });
	} catch (err) {
		console.error(err.message);
		res.status(500).send("Server Error");
	}
});

// login
app.post("/login", async (req, res) => {
	try {
		const { email, password } = req.body;
		const user = await User.findOne({ email });
		if (!user) {
			return res.status(404).send("User not found");
		}

		// Compare hashed passwords
		const passwordMatch = await bcrypt.compare(password, user.password);
		if (!passwordMatch) {
			return res.status(400).send("Invalid password");
		}

		// Generate token
		const payload = {
			user: {
				id: user.id,
			},
		};
		jwt.sign(
			payload,
			process.env.JWT_SECRET,
			{ expiresIn: 360000000000 },
			(err, token) => {
				if (err) {
					console.error(err.message);
					return res.status(500).send("Server error");
				}
				return res.json({ token });
			}
		);
	} catch (err) {
		console.error(err.message);
		return res.status(500).send("Server error");
	}
});

app.get("/allUsers", middleware, async (req, res) => {
	try {
		// Check if the user is an admin
		if (req.user.role === "admin") {
			// If user is admin, fetch all users
			let allUsers = await User.find();
			return res.json(allUsers);
		} else {
			// If user is not admin, fetch only public users
			let publicUsers = await User.find({ isPublic: true });
			return res.json(publicUsers);
		}
	} catch (err) {
		console.log(err.message);
		res.status(500).send("Internal server error");
	}
});

// Route to get current user's profile
app.get("/myProfile", middleware, async (req, res) => {
	try {
		console.log(`req.user.id : ${req.user.id}`);
		let user = await User.findById(req.user.id);
		return res.json(user);
	} catch (err) {
		console.log(err.message);
		return res.status(500).send("Server Error");
	}
});

// editing user profile

app.put("/editProfile", authenticateJwt, async (req, res) => {
	try {
		// Extract updated user details from the request body
		const { name, bio, phoneNumber, email, password, isPublic, photo, role } =
			req.body;
		// Find the user by ID
		let user = await User.findById(req.user.id);
		if (!user) {
			return res.status(404).json({ message: "User not found" });
		}
		// Update user details
		user.name = name;
		user.bio = bio;
		user.phoneNumber = phoneNumber;
		user.email = email;
		user.isPublic = isPublic;
		user.photo = photo;
		user.role = role;
		// Hash and update password if provided
		if (password) {
			const salt = await bcrypt.genSalt(10);
			user.password = await bcrypt.hash(password, salt);
		}
		// Save updated user details
		await user.save();
		return res
			.status(200)
			.json({ message: "User details updated successfully" });
	} catch (err) {
		console.error(err.message);
		return res.status(500).send("Server Error");
	}
});

app.listen(process.env.PORT, () => {
	console.log(`Server started on Port ${process.env.PORT}`);
});
