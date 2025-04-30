import express from "express";
import mongoose from "mongoose";
import 'dotenv/config';
import bcrypt from "bcrypt";
import User from "./Schema/User.js";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import { createRequire } from "module";
import aws from "aws-sdk";
import Blog from "./Schema/Blog.js";
import nodemailer from "nodemailer";
import otpGenerator from "otp-generator";
import dns from "dns";
import { promisify } from "util";
import Notification from "./Schema/Notification.js";
import Comment from "./Schema/Comment.js";
import crypto from 'crypto';

const require = createRequire(import.meta.url);
const serviceAccountKey = require("./blogwebsite-79574-firebase-adminsdk-fbsvc-f114d3e651.json");
import { getAuth } from "firebase-admin/auth";
import { error } from "console";
import path from "path";

const server = express();
let PORT = 3000;

// Promisify dns.resolve for async/await
const resolveMx = promisify(dns.resolveMx);

// In-memory storage for OTPs (use Redis or MongoDB for production)
const otpStorage = new Map();

admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey)
});

// Stricter email regex (from second file)
let emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

server.use(express.json());
server.use(cors());

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true
});

// Nodemailer setup (Gmail) - from second file
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Replace existing sendOTP function in server.js
const sendOTP = async (email, type) => {
    const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false });
    const normalizedEmail = email.toLowerCase(); // Normalize email to lowercase
    otpStorage.set(normalizedEmail, { otp, expires: Date.now() + 10 * 60 * 1000 }); // 10 minutes expiry
    console.log(`OTP Generated for ${normalizedEmail} (${type}): ${otp}`);
    console.log(`otpStorage after set:`, otpStorage.get(normalizedEmail));
  
    let subject, text;
    switch (type) {
      case 'signup':
      case 'signin':
        subject = 'Email Verification OTP';
        text = `Your OTP for email verification is: ${otp}. It expires in 10 minutes.`;
        break;
      case 'forgot-password':
        subject = 'Password Reset OTP';
        text = `Your OTP for password reset is: ${otp}. It expires in 10 minutes.`;
        break;
      default:
        throw new Error('Invalid OTP type');
    }
  
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email, // Use original email for sending
      subject,
      text,
    };
  
    await transporter.sendMail(mailOptions);
    console.log(`OTP Email sent to ${email}`);
    return otp;
  };



// Verify OTP - from second file
const verifyOTP = (email, otp) => {
    const stored = otpStorage.get(email);
    if (!stored) return { valid: false, error: "OTP not found or expired" };
    if (stored.expires < Date.now()) {
        otpStorage.delete(email);
        return { valid: false, error: "OTP expired" };
    }
    if (stored.otp !== otp) return { valid: false, error: "Invalid OTP" };
    otpStorage.delete(email);
    return { valid: true };
};

// Function to verify email domain existence - from second file
const verifyEmailDomain = async (email) => {
    const domain = email.split('@')[1];
    try {
        const mxRecords = await resolveMx(domain);
        return mxRecords && mxRecords.length > 0;
    } catch (err) {
        console.error(`DNS lookup failed for ${domain}:`, err.message);
        return false;
    }
};

// Middleware and utility functions (common in both files)
const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];
    if (token == null) {
        return res.status(401).json({ error: "No access token" });
    }
    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if (err) {
            return res.status(401).json({ error: "Access token is invalid" });
        }
        req.user = user.id;
        next();
    });
};

const formatDatatoSend = (user) => {
    const access_token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY);
    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname
    };
};

const generateUsername = async (email) => {
    let username = email.split("@")[0];
    let isUsernameNotUnique = await User.exists({ "personal_info.username": username }).then((result) => result);
    isUsernameNotUnique ? username += nanoid().substring(0, 5) : "";
    return username;
};

// S3 setup (common in both files)
const s3 = new aws.S3({
    region: 'ap-south-1',
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

const generateUploadURL = async () => {
    const date = new Date();
    const imageName = `${nanoid()}-${date.getTime()}.jpeg`;
    return await s3.getSignedUrlPromise('putObject', {
        Bucket: 'blogging-webpage',
        Key: imageName,
        Expires: 1000,
        ContentType: "image/jpeg"
    });
};

// Routes

// Upload image URL route (common in both files)
server.get('/get-upload-url', (req, res) => {
    generateUploadURL()
        .then(url => res.status(200).json({ uploadURL: url }))
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        });
});

// Replace existing /request-otp route in server.js
server.post('/request-otp', async (req, res) => {
    const { email, type } = req.body;
    if (!email || !emailRegex.test(email)) {
      console.log('Invalid email format:', email);
      return res.status(403).json({ error: 'Invalid Email' });
    }
  
    const normalizedEmail = email.toLowerCase(); // Normalize email
    console.log(`Request OTP for: ${normalizedEmail}, Type: ${type}`);
  
    const isDomainValid = await verifyEmailDomain(email);
    if (!isDomainValid) {
      console.log(`Invalid email domain for ${normalizedEmail}`);
      return res.status(403).json({ error: 'Invalid Email' });
    }
  
    try {
      const user = await User.findOne({ 'personal_info.email': normalizedEmail });
      if (type === 'signin') {
        if (!user) {
          console.log(`User not found for ${normalizedEmail}`);
          return res.status(403).json({ error: 'Email not found. Please sign up first.' });
        }
        if (user.google_auth) {
          console.log(`Google auth user: ${normalizedEmail}`);
          return res.status(403).json({ error: 'This email is registered with Google. Please use Google to sign in.' });
        }
      } else if (type === 'signup') {
        if (user) {
          console.log(`User already exists for ${normalizedEmail}`);
          return res.status(403).json({ error: 'Email already exists. Please sign in instead.' });
        }
      } else {
        console.log('Invalid request type:', type);
        return res.status(400).json({ error: 'Invalid request type' });
      }
  
      await sendOTP(email, type);
      return res.status(200).json({ message: 'OTP sent to your email' });
    } catch (err) {
      console.error('Error sending OTP:', err);
      return res.status(500).json({ error: 'Failed to send OTP' });
    }
  });

// Replace existing /verify-otp route in server.js
server.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
      console.log('Missing email or OTP:', { email, otp });
      return res.status(403).json({ error: 'Email and OTP are required' });
    }
  
    const normalizedEmail = email.toLowerCase(); // Normalize email
    console.log(`Verifying OTP for: ${normalizedEmail}, OTP: ${otp}`);
    console.log(`otpStorage contents:`, otpStorage.get(normalizedEmail));
  
    const stored = otpStorage.get(normalizedEmail);
    if (!stored) {
      console.log(`No OTP found in otpStorage for ${normalizedEmail}`);
      return res.status(403).json({ error: 'OTP not found. Request a new OTP.' });
    }
    if (stored.expires < Date.now()) {
      otpStorage.delete(normalizedEmail);
      console.log(`OTP expired for ${normalizedEmail}`);
      return res.status(403).json({ error: 'OTP has expired. Request a new OTP.' });
    }
    if (stored.otp !== otp) {
      console.log(`Invalid OTP for ${normalizedEmail}. Expected: ${stored.otp}, Received: ${otp}`);
      return res.status(403).json({ error: 'Invalid OTP. Please try again.' });
    }
  
    otpStorage.delete(normalizedEmail);
    console.log(`OTP verified successfully for ${normalizedEmail}`);
    return res.status(200).json({ message: 'OTP verified successfully' });
  });


// Replace existing /forgot-password route
// Replace existing /forgot-password route in server.js
server.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email || !emailRegex.test(email)) {
      console.log('Invalid email format:', email);
      return res.status(403).json({ error: 'Invalid email' });
    }
  
    const normalizedEmail = email.toLowerCase(); // Normalize email
    console.log(`Forgot Password Request for: ${normalizedEmail}`);
  
    try {
      const user = await User.findOne({ 'personal_info.email': normalizedEmail });
      if (!user) {
        console.log(`User not found for ${normalizedEmail}`);
        return res.status(404).json({ error: 'No account found with this email' });
      }
      if (user.google_auth) {
        console.log(`Google auth user: ${normalizedEmail}`);
        return res.status(403).json({ error: 'This account uses Google authentication. Password reset is not available.' });
      }
  
      const isDomainValid = await verifyEmailDomain(email);
      if (!isDomainValid) {
        console.log(`Invalid email domain for ${normalizedEmail}`);
        return res.status(403).json({ error: 'Invalid email domain' });
      }
  
      await sendOTP(email, 'forgot-password');
      return res.status(200).json({ message: 'OTP sent to your email' });
    } catch (err) {
      console.error('Error in forgot password:', err);
      return res.status(500).json({ error: 'Failed to send OTP. Please try again later.' });
    }
  });


 // Add after other routes
// Replace or add /resend-otp route in server.js
server.post('/resend-otp', async (req, res) => {
    const { email, type } = req.body;
    if (!email || !emailRegex.test(email)) {
      console.log('Invalid email format:', email);
      return res.status(403).json({ error: 'Invalid email' });
    }
    if (!['signup', 'signin', 'forgot-password'].includes(type)) {
      console.log('Invalid request type:', type);
      return res.status(400).json({ error: 'Invalid request type' });
    }
  
    const normalizedEmail = email.toLowerCase(); // Normalize email
    console.log(`Resend OTP Request for: ${normalizedEmail}, Type: ${type}`);
  
    try {
      const user = await User.findOne({ 'personal_info.email': normalizedEmail });
      if (type === 'signin' || type === 'forgot-password') {
        if (!user) {
          console.log(`User not found for ${normalizedEmail}`);
          return res.status(404).json({ error: 'No account found with this email' });
        }
        if (user.google_auth) {
          console.log(`Google auth user: ${normalizedEmail}`);
          return res.status(403).json({ error: 'This account uses Google authentication.' });
        }
      } else if (type === 'signup') {
        if (user) {
          console.log(`User already exists for ${normalizedEmail}`);
          return res.status(403).json({ error: 'Email already exists. Please sign in instead.' });
        }
      }
  
      const isDomainValid = await verifyEmailDomain(email);
      if (!isDomainValid) {
        console.log(`Invalid email domain for ${normalizedEmail}`);
        return res.status(403).json({ error: 'Invalid email domain' });
      }
  
      await sendOTP(email, type);
      return res.status(200).json({ message: 'OTP resent to your email' });
    } catch (err) {
      console.error('Error resending OTP:', err);
      return res.status(500).json({ error: 'Failed to resend OTP. Please try again later.' });
    }
  });

  // Replace existing /reset-password route in server.js
server.post('/reset-password', async (req, res) => {
    const { email, newPassword, confirmPassword } = req.body;
    if (!email || !newPassword || !confirmPassword) {
      console.log('Missing required fields:', { email, newPassword, confirmPassword });
      return res.status(403).json({ error: 'Email, new password, and confirm password are required' });
    }
    if (!emailRegex.test(email)) {
      console.log('Invalid email format:', email);
      return res.status(403).json({ error: 'Invalid email' });
    }
    if (newPassword !== confirmPassword) {
      console.log('Passwords do not match');
      return res.status(403).json({ error: 'Passwords do not match' });
    }
    if (!passwordRegex.test(newPassword)) {
      console.log('Invalid password format');
      return res.status(403).json({ error: 'Password should be 6 to 20 characters long with a numeric, 1 lowercase, and 1 uppercase letter' });
    }
  
    try {
      const normalizedEmail = email.toLowerCase(); // Normalize email
      console.log(`Reset Password for: ${normalizedEmail}`);
      const user = await User.findOne({ 'personal_info.email': normalizedEmail });
      if (!user) {
        console.log(`User not found for ${normalizedEmail}`);
        return res.status(404).json({ error: 'No account found with this email' });
      }
      if (user.google_auth) {
        console.log(`Google auth user: ${normalizedEmail}`);
        return res.status(403).json({ error: 'This account uses Google authentication. Password reset is not available.' });
      }
  
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.personal_info.password = hashedPassword;
      await user.save();
      console.log(`Password reset successfully for ${normalizedEmail}`);
  
      return res.status(200).json({ message: 'Password reset successfully' });
    } catch (err) {
      console.error('Error in reset password:', err);
      return res.status(500).json({ error: 'Failed to reset password. Please try again later.' });
    }
  });

// Signup route - from second file (with OTP)
server.post("/signup", async (req, res) => {
    let { fullname, email, password, otp } = req.body;

    if (fullname.length < 3) {
        return res.status(403).json({ error: "Fullname must be at least 3 letters long" });
    }
    if (!email.length) {
        return res.status(403).json({ error: "Enter Email" });
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ error: "Invalid Email" });
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ error: "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letter" });
    }
    if (!otp) {
        return res.status(403).json({ error: "OTP required for verification" });
    }

    const otpResult = verifyOTP(email, otp);
    if (!otpResult.valid) {
        return res.status(403).json({ error: otpResult.error });
    }

    bcrypt.hash(password, 10, async (err, hashed_password) => {
        if (err) {
            return res.status(500).json({ error: "Error hashing password" });
        }
        let username = await generateUsername(email);
        let user = new User({
            personal_info: { fullname, email, password: hashed_password, username }
        });

        user.save()
            .then((u) => res.status(200).json(formatDatatoSend(u)))
            .catch(err => {
                if (err.code == 11000) {
                    return res.status(500).json({ error: "E-mail already exists" });
                }
                return res.status(403).json({ error: err.message });
            });
    });
});

// Signin route (common in both files)
server.post("/signin", (req, res) => {
    let { email, password } = req.body;
    User.findOne({ "personal_info.email": email })
        .then((user) => {
            if (!user) {
                return res.status(403).json({ "error": "Email not found" });
            }
            if (!user.google_auth) {
                bcrypt.compare(password, user.personal_info.password, (err, result) => {
                    if (err) {
                        return res.status(403).json({ "error": "Error occurred while login, Please try again" });
                    }
                    if (!result) {
                        return res.status(403).json({ "error": "Incorrect Password" });
                    } else {
                        return res.status(200).json(formatDatatoSend(user));
                    }
                });
            } else {
                return res.status(403).json({ "error": "Account was created using Google. Try logging in with Google" });
            }
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ "error": err.message });
        });
});

// Google Auth route (common in both files)
server.post("/google-auth", async (req, res) => {
    const { access_token } = req.body;
    if (!access_token || typeof access_token !== "string") {
        return res.status(400).json({ error: "Invalid or missing access token" });
    }
    try {
        const decodedUser = await getAuth().verifyIdToken(access_token);
        const { email, name, picture } = decodedUser;
        const profile_img = picture.replace("s96-c", "s384-c");
        let user = await User.findOne({ "personal_info.email": email })
            .select("personal_info.fullname personal_info.username personal_info.profile_img google_auth")
            .exec();
        if (user) {
            if (!user.google_auth) {
                return res.status(403).json({
                    error: "This email was signed up without Google. Please log in with password to access the account"
                });
            }
        } else {
            const username = await generateUsername(email);
            user = new User({
                personal_info: { fullname: name, email, profile_img, username },
                google_auth: true
            });
            await user.save();
        }
        return res.status(200).json(formatDatatoSend(user));
    } catch (err) {
        console.error("Google auth error:", err);
        return res.status(500).json({ error: "Failed to authenticate you. Try with another Google account" });
    }
});


server.post('/change-password', verifyJWT, (req, res) => {
    let { currentPassword, newPassword } = req.body;

    if (!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)) {
        return res.status(403).json({ error: "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letter" })
    }

    User.findOne({ _id: req.user })
        .then((user) => {
            if (user.google_auth) {
                return res.status(403).json({ error: "You cannot change account's password as you logged in through Google" })
            }
            bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
                if (err) {
                    return res.status(403).json({ error: "Some error occured while changing the password,please try again later" })
                }
                if (!result) {
                    return res.status(403).json({ error: "Incorrect Current Password " })
                }

                bcrypt.hash(newPassword, 10, (err, hashed_password) => {
                    User.findOneAndUpdate({ _id: req.user }, { "personal_info.password": hashed_password })
                        .then((u) => {
                            return res.status(200).json({ status: "Password Changed" })
                        })
                        .catch(err => {
                            return res.status(500).json({ error: "Some error occured while saving new password, please try again later " })
                        })
                })
            })
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({ error: "User not found " })
        })
})




// Latest Blogs route - from first file (with pagination)
server.post('/latest-blogs', (req, res) => {
    let { page } = req.body;
    let maxLimit = 4;

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title banner title des activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});

// Trending Blogs route - from first file (updated to fix syntax error)
server.get('/trending-blogs', (req, res) => {
    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "activity.total_reads": -1, "activity.total_likes": -1, "publishedAt": -1 }) // Fixed syntax
        .select("blog_id title publishedAt -_id")
        .limit(5)
        .then(blogs => {
            return res.status(200).json({ blogs });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});

// All Latest Blogs Count route - from first file
server.post("/all-latest-blogs-count", (req, res) => {
    Blog.countDocuments({ draft: false })
        .then(count => {
            return res.status(200).json({ totalDocs: count });
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        });
});

// Search Blogs route - from first file
server.post("/search-blogs", (req, res) => {
    let { tag, query, author, page, limit, eliminate_blog } = req.body;
    let findQuery;

    if (tag) {
        findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_blog } };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') };
    } else if (author) {
        findQuery = { author, draft: false };
    }

    let maxLimit = limit ? limit : 2

    Blog.find(findQuery)
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title banner title des activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});

// Search Blogs Count route - from first file
server.post("/search-blogs-count", (req, res) => {
    let { tag, author, query } = req.body;
    let findQuery;

    if (tag) {
        findQuery = { tags: tag, draft: false };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i') };
    } else if (author) {
        findQuery = { author, draft: false };
    }


    Blog.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count });
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message });
        });
});

// Search Users route - from first file
server.post("/search-users", (req, res) => {
    let { query } = req.body;
    User.find({
        $or: [
            { "personal_info.username": new RegExp(query, 'i') },
            { "personal_info.fullname": new RegExp(query, 'i') }
        ]
    })
        .limit(50)
        .select("personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .then(users => {

            return res.status(200).json({ users });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});

server.post('/get-profile', (req, res) => {
    let { username } = req.body;
    User.findOne({
        $or: [
            { "personal_info.username": new RegExp(username, 'i') },
            { "personal_info.fullname": new RegExp(username, 'i') }
        ]
    })
        .select("-personal_info.password -google_auth -updatedAt -blogs")
        .then(user => {
            return res.status(200).json(user)
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/updated-profile-img', verifyJWT, (req, res) => {
    let { url } = req.body;
    User.findOneAndUpdate({ _id: req.user }, { 'personal_info.profile_img': url })
      .then(() => {
        return res.status(200).json({ profile_img: url });
      })
      .catch(err => {
        return res.status(500).json({ error: err.message });
      });
  });


server.post('/update-profile', verifyJWT ,(req,res) => {
    let { username,bio, social_links } = req.body;
    let bioLimit = 150;

    if(username.length < 3){
        return res.status(403).json({ error: "Username should be atleast 3 letters long " })
    }
    if(bio.length > bioLimit ){
        return res.status(403).json({ error: `Bio should not be more than ${bioLimit} characters` })
    }

    let socialLinksArr  = Object.keys(social_links);
    try{
        for(let i = 0;i < socialLinksArr.length;i++){
            if(social_links[socialLinksArr[i]].length){
                let hostname = new URL(social_links[socialLinksArr[i]]).hostname; 
                if(!hostname.includes(`${socialLinksArr[i]}.com`) && socialLinksArr[i] != 'website'){
                    return res.status(403).json({error:`This ${socialLinksArr[i]} link is invalid you must enter full links `})
                }
            }
        }

    }catch(err){
        return res.status(500).json({error: "You must provide full social links with http(s) included"})
    }
    let updateObj = {
        "personal_info.username": username,
        "personal_info.bio": bio,
        social_links

    }
    User.findOneAndUpdate({ _id:req.user }, updateObj,{
        runValidators:true

    })
    .then(() => {
        return res.status(200).json({ username })
    })
    .catch(err => {
        if(err.code == 1100){
            return res.status(409).json({ error: "Username is already taken" })
        }
        return res.status(500).json({ error: err.message })
    })

})


// Create Blog route (common in both files)
server.post('/create-blog', verifyJWT, (req, res) => {
    let authorId = req.user;
    let { title, des, banner, tags, content, draft, id } = req.body;

    if (!title.length) {
        return res.status(403).json({ error: "You must provide a title" }); // Fixed status code (4013 to 403)
    }

    if (!draft) {
        if (!des.length || des.length > 200) {
            return res.status(403).json({ error: "You must provide the description under 200 characters" });
        }
        if (!banner.length) {
            return res.status(403).json({ error: "You must provide the blog banner to publish it" });
        }
        if (!content.blocks.length) {
            return res.status(403).json({ error: "There must be some blog content to publish it" });
        }
        if (!tags.length) {
            return res.status(403).json({ error: "Provide the tags in order to publish the Blog" });
        }
    }

    tags = tags.map(tag => tag.toLowerCase());
    let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim() + nanoid();
    if (id) {
        Blog.findOneAndUpdate({ blog_id }, { title, des, banner, tags, content, draft: draft ? draft : false })
            .then(() => {
                return res.status(200).json({ id: Blog.blog_id })
            })
            .catch(err => {
                return res.status(500).json({ error: err.message })
            })

    } else {
        let blog = new Blog({
            title, des, banner, content, tags, author: authorId, blog_id, draft: Boolean(draft)
        });

        blog.save()
            .then(blog => {
                let incrementVal = draft ? 0 : 1;
                User.findOneAndUpdate(
                    { _id: authorId },
                    { $inc: { "account_info.total_posts": incrementVal }, $push: { "blogs": blog._id } }
                )
                    .then(user => res.status(200).json({ id: blog.blog_id }))
                    .catch(err => res.status(500).json({ error: "Failed to update total posts number" }));
            })
            .catch(err => res.status(500).json({ error: err.message }));
    }
});


server.post('/get-blog', (req, res) => {
    let { blog_id, draft, mode } = req.body;
    let incrementVal = mode != 'edit' ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id }, { $inc: { "activity.total_reads": incrementVal } })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname")
        .select("blog_id title banner des content activity tags publishedAt")
        .then(blog => {
            User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username }, {
                $inc: { "account_info.total_reads": incrementVal }
            })
                .catch(err => {
                    return res.status(500).json({ error: err.message })
                })

            if (blog.draft && !draft) {
                return res.status(500).json({ error: 'You cannot access this blog, it is a draft' })
            }


            return res.status(200).json({ blog });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })


});


server.post('/like-blog', verifyJWT, (req, res) => {
    let user_id = req.user;
    let { _id, islikedByUser } = req.body;
    let incrementVal = !islikedByUser ? 1 : -1;

    Blog.findOneAndUpdate({ _id, }, { $inc: { "activity.total_likes": incrementVal } })
        .then(blog => {
            if (!islikedByUser) {
                let like = new Notification({
                    type: "like",
                    user: user_id,
                    notification_for: blog.author,
                    blog: _id,
                })
                like.save().then(notification => {
                    return res.status(200).json({ like_by_user: true })
                })
            }
            else {
                Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like" })
                    .then(() => {
                        return res.status(200).json({ like_by_user: false })
                    })
                    .catch(err => {
                        return res.status(500).json({ error: err.message })
                    })
            }
        })
})

server.post('/isliked-by-user', verifyJWT, (req, res) => {
    let user_id = req.user;
    let { _id } = req.body;
    Notification.exists({ user: user_id, blog: _id, type: "like" })
        .then(result => {
            return res.status(200).json({ result })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })


});

server.post('/add-comment', verifyJWT, (req, res) => {
    let user_id = req.user;
    let { _id, comment, replying_to, blog_author,notification_id  } = req.body;

    if (!comment.length) {
        return res.status(403).json({ error: "Write something to leave a comment...." })
    }
    let commentObj = {
        blog_id: _id, blog_author, comment, commented_by: user_id,

    }

    if (replying_to) {
        commentObj.parent = replying_to;
        commentObj.isReply = true;

    }

    new Comment(commentObj).save().then(async commentFile => {
        let { comment, commentedAt, children } = commentFile;
        Blog.findOneAndUpdate({ _id }, { $push: { "comments": commentFile._id }, $inc: { "activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 } })
            .then(blog => { console.log('new comment created') });

        let notificationObj = {
            type: replying_to ? "reply" : "comment",
            blog: _id,
            notification_for: blog_author,
            user: user_id,
            comment: commentFile._id,


        }

        if (replying_to) {
            notificationObj.replied_on_comment = replying_to;
            await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: commentFile._id } })
                .then(replyingToCommentDoc => { notificationObj.notification_for = replyingToCommentDoc.commented_by })
                if(notification_id){
                    Notification.findOneAndUpdate({ _id: notification_id },{ reply:commentFile._id })
                    .then(notification => console.log('notification updated'))
                }
        }

        new Notification(notificationObj).save().then(notification => console.log('new comment notification created'));
        return res.status(200).json({ comment, commentedAt, _id: commentFile._id, user_id, children })
    })

})


server.post('/get-blog-comments', (req, res) => {
    let { blog_id, skip } = req.body;
    let maxLimit = 5;

    Comment.find({ blog_id, isReply: false })
        .populate("commented_by", "personal_info.profile_img personal_info.username personal_info.fullname")
        .skip(skip)
        .limit(maxLimit)
        .sort({
            'commentedAt': -1
        })
        .then(comment => {
            return res.status(200).json(comment);
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/get-replies', (req, res) => {
    let { _id, skip } = req.body;
    let maxLimit = 3;
    Comment.findOne({ _id })
        .populate({
            path: "children",
            options: {
                limit: maxLimit,
                skip: skip,
                sort: { 'commentedAt': -1 }

            },
            populate: {
                path: 'commented_by',
                select: 'personal_info.profile_img personal_info.username personal_info.fullname'
            },
            select: "-blog_id -updatedAt "
        })
        .select("children")
        .then(doc => {
            return res.status(200).json({ replies: doc.children })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

const deleteComments = async (_id) => {
    try {
        const comment = await Comment.findOneAndDelete({ _id });
        if (!comment) return;

        // Remove from parent
        if (comment.parent) {
            await Comment.findOneAndUpdate(
                { _id: comment.parent },
                { $pull: { children: _id } }
            );
        }

        // Delete notifications
        await Notification.findOneAndDelete({ comment: _id });
        await Notification.findOneAndUpdate({ reply: _id },{$unset: { reply:1  }});

        // Update blog: fix `$pull` typo and conditional `$inc`
        await Blog.findOneAndUpdate(
            { _id: comment.blog_id },
            {
                $pull: { comments: _id },
                $inc: {
                    "activity.total_comments": -1,
                    ...(comment.parent ? {} : { "activity.total_parent_comments": -1 })
                }
            }
        );

        // Recursively delete children comments
        if (comment.children?.length) {
            for (const childId of comment.children) {
                await deleteComments(childId);
            }
        }

    } catch (err) {
        console.error("Error deleting comment:", err.message);
    }
};


server.post('/delete-comment', verifyJWT, (req, res) => {

    let user_id = req.user;
    let { _id } = req.body;
    Comment.findOne({ _id })
        .then(comment => {
            if (user_id == comment.commented_by || user_id == comment.blog_author) {
                deleteComments(_id)

                return res.status(200).json({ status: "Deleted" })

            }
            else {
                return res.status(403).json({ error: "You cannot delete this comment" })
            }
        })
})

server.get("/new-notification", verifyJWT, (req,res) => {
    let user_id = req.user;

    Notification.exists({ notification_for: user_id,seen: false,user : { $ne: user_id }})
    .then(result => {
        if(result){
            return res.status(200).json({ new_notification_available: true })
        }
        else{
            return res.status(200).json({ new_notification_available:false }) 
        }
    })
    .catch(err => {
        return res.status(500).json({ error :err.message })
    })
})

server.post("/notifications", verifyJWT, (req,res) =>{
    let user_id = req.user;
    let { page,filter, deletedDocCount  } = req.body;
    let maxLimit = 10;
    let findQuery = { notification_for: user_id, user : { $ne : user_id } }
    let skipDocs = ( page - 1 ) * maxLimit;
    if( filter != 'all' ){
        findQuery.type = filter;
    }
    if(deletedDocCount){
        skipDocs -= deletedDocCount;

    }

    Notification.find(findQuery)
    .skip(skipDocs)
    .limit(maxLimit)
    .populate("blog", "title blog_id")
    .populate("user", "personal_info.fullname personal_info.username personal_info.profile_img")
    .populate("comment","comment")
    .populate("replied_on_comment","comment")
    .populate("reply", "comment")
    .sort({ createdAt:-1 })
    .select("createdAt type seen reply")
    .then(notifications => {
        Notification.updateMany(findQuery, { seen:true })
        .skip(skipDocs)
        .limit(maxLimit)
        .then(() => console.log('seen Nf'))
        return res.status(200).json({ notifications })
    })
    .catch(err => {
        console.log(err);
        return res.status(500).json({ error: err.message })
    })
})


server.post("/all-notifications-count", verifyJWT, (req,res) =>{
    let user_id = req.user;
    let { filter } = req.body;
    let findQuery = { notification_for: user_id, user:{ $ne: user_id }}
    if(filter != 'all'){
        findQuery.type = filter;
    }

    Notification.countDocuments(findQuery)
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
})


server.post('/user-written-blogs', verifyJWT,(req,res) => {
    let user_id = req.user;
    let { page,draft, query,deletedDocCount } = req.body;
    let maxLimit = 5;
    let skipDocs = (page-1)*maxLimit;
    if(deletedDocCount){
        skipDocs -= deletedDocCount;
    }
    Blog.find({ author: user_id, draft, title: new RegExp(query,'i')})
    .skip(skipDocs)
    .limit(maxLimit)
    .sort({ publishedAt: -1 })
    .select("title banner blog_id publishedAt activity des draft -_id")
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(200).json({ error:err.message })
    })
})


server.post('/user-written-blogs-count', verifyJWT,(req,res)=> {
     let user_id = req.user;
     let { draft, query } = req.body;

     Blog.countDocuments({  author: user_id,draft,title: new RegExp(query,'i')})
     .then(count => {
        return res.status(200).json({ totalDocs: count })
     })
     .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error:err.message  })

     })
})

server.post("/delete-blog", verifyJWT,(req,res) => {
    let user_id  = req.user
    let { blog_id } = req.body;
    Blog.findOneAndDelete({ blog_id })
    .then(blog => {
      Notification.deleteMany({ blog: blog._id }).then(data => console.log('notification deleted'))
      Comment.deleteMany({ blog_id: blog._id }).then(data => console.log('comments deleted'))

      User.findOneAndUpdate({ _id:user_id },{ $pull: { blog: blog._id }, $inc: { "account_info.total_posts":-1 } })
      .then(user => console.log('Blog Deleted'))
      return res.status(200).json({ status:'Done deleted' })
    }) 
    .catch(err => {
        return res.status(500).json({ error:err.message })
        console.log(err.message)

    })
})


// Start the server (with binding to 0.0.0.0 for mobile access)
server.listen(PORT, '0.0.0.0', () => {
    console.log('Listening on port -> ' + PORT);
});