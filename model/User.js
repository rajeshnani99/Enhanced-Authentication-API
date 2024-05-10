/** @format */

// models/User.js

const { type } = require("express/lib/response");
const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
	email: {
		type: String,
		required: true,
		unique: true,
	},
	password: {
		type: String,
		required: true,
	},
	name: {
		type: String,
		required: true,
	},
	bio: {
		type: String,
	},
	photo: {
		type: String, // Assuming the photo is stored as a URL or file path
	},
	phoneNumber: {
		type: String,
	},
	role: {
		type: String,
		enum: ["user", "admin"],
		default: "user",
	},
	isPublic: {
		type: Boolean,
		default: true,
	},
});

module.exports = mongoose.model("User", UserSchema);
