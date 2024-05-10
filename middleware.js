/** @format */

// @ts-nocheck
/** @format */
// some other way to verify the user
const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
	try {
		let token = req.header("x-token");
		if (!token) {
			return res.status(400).send("Token not found");
		}
		let decoded = jwt.verify(token, "jwtPassword");
		req.user = decoded.user;
		console.log(`decoded :: ${req}`);
		next();
	} catch (err) {
		console.log(err.message);
		return res.status(400).send("Authentication error");
	}
};
