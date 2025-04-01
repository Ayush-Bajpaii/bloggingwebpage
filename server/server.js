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



const require = createRequire(import.meta.url);
const serviceAccountKey = require("./blogwebsite-79574-firebase-adminsdk-fbsvc-f114d3e651.json");
import { getAuth  } from "firebase-admin/auth";





const server = express();
let PORT = 3000;

admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey)
})

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

server.use(express.json());
server.use(cors());

mongoose.connect(process.env.DB_LOCATION,{
    autoIndex:true
})

    //setting up s3 bucket
    const s3 = new aws.S3({
        region:'ap-south-1',
        accessKeyId : process.env.AWS_ACCESS_KEY,
        secretAccessKey : process.env.AWS_SECRET_ACCESS_KEY
    })


    const generateUploadURL = async () => {
        const date = new Date();
        const imageName = `${nanoid()}-${date.getTime()}.jpeg`

       return await  s3.getSignedUrlPromise('putObject',{
            Bucket:'blogging-webpage',
            Key: imageName,
            Expires: 1000,
            ContentType:"image/jpeg"
        })

    }


    const formatDatatoSend = (user) => {
        const access_token = jwt.sign({id: user._id}, process.env.SECRET_ACCESS_KEY)

        return {
            access_token,
            profile_img: user.personal_info.profile_img,
            username: user.personal_info.username,
            fullname: user.personal_info.fullname
        }
    }

    const generateUsername = async (email) => {
        let username = email.split("@")[0];

        let isUsernameNotUnique = await User.exists({"personal_info.username": username}).then((result) => result)
        isUsernameNotUnique ? username += nanoid().substring(0, 5) : "";
        return username;
    };


    //upload image url route
    server.get('/get-upload-url', (req,res) => {
        generateUploadURL().then(url => res.status(200).json({uploadURL: url}))
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message })
        })
    })
    

server.post("/signup", (req,res) =>{
    let { fullname, email, password } = req.body;

    //validating the data from frontend
    if(fullname.length<3){
        return res.status(403).json({ "error":"Fullname must be atleast 3 letters long" })
    }

    if(!email.length){
        return res.status(403).json({ "error": "Enter Email"})
    }
    if(!emailRegex.test(email)){
        return res.status(403).json({"error": "email is invalid"})
    }
    if(!passwordRegex.test(password)){
        return res.status(403).json({"error":"Password should be 6 to 20 characters long with a numeric,1 lowercase and 1 uppercase letter"})
    }
    bcrypt.hash(password,10, async (err,hashed_password)=> {
        let username = await generateUsername(email);

        let user = new User({
            personal_info:{ fullname,email,password : hashed_password, username }
        })

        user.save().then((u) =>{
            return res.status(200).json(formatDatatoSend(u))
        })
        .catch(err => {
            if(err.code == 11000){
                return res.status(500).json({ "error":"E-mail already exists"})
            }

            return res.status(403).json({ "error": err.message})
        })
    })
    
})

        server.post("/signin",(req,res) =>{
            let { email,password } = req.body;
            User.findOne({"personal_info.email": email}).then((user) =>{
                if(!user){
                    return res.status(403).json({"error":"Email not found"})
                }

                if(!user.google_auth){
                    bcrypt.compare(password, user.personal_info.password, (err, result) => {
                        if(err){
                            return res.status(403).json({"error":"Error occured while login, Please try again"}) 
                        }
                        if(!result){
                            return res.status(403).json({"error":"Incorrect Password"})
                        }else{
                            return res.status(200).json(formatDatatoSend(user))
                        }
    
                    })

                }

                else{
                    return res.status(403).json({"error":"Account was created using Google.Try logging in with google"})
                }

                // console.log(user)
                // return res.json({"status":"got user document"})
            }).catch(err =>{
                console.log(err.message);
                return res.status(500).json({"error":err.message})
            })

        })

        server.post("/google-auth", async (req, res) => {
            const { access_token } = req.body;
          
            // Validate input
            if (!access_token || typeof access_token !== "string") {
              return res.status(400).json({ error: "Invalid or missing access token" });
            }
          
           // console.log("Received access_token:", access_token); // Debug log
          
            try {
              // Verify Firebase ID token
              const decodedUser = await getAuth().verifyIdToken(access_token);
              const { email, name, picture } = decodedUser;
          
              // Adjust picture size
              const profile_img = picture.replace("s96-c", "s384-c");
          
              // Check if user exists
              let user = await User.findOne({ "personal_info.email": email })
                .select("personal_info.fullname personal_info.username personal_info.profile_img google_auth")
                .exec();
          
              if (user) {
                // Login case
                if (!user.google_auth) {
                  return res.status(403).json({
                    error: "This email was signed up without Google. Please log in with password to access the account",
                  });
                }
              } else {
                // Signup case
                const username = await generateUsername(email);
                user = new User({
                  personal_info: { fullname: name, email, profile_img, username },
                  google_auth: true,
                });
                await user.save();
              }
          
              // Send response
              return res.status(200).json(formatDatatoSend(user));
            } catch (err) {
              console.error("Google auth error:", err); // Log full error for debugging
              return res.status(500).json({ error: "Failed to authenticate you. Try with another Google account" });
            }
          });

server.listen(PORT,() => {
    console.log('Listening on port ->' + PORT);
});
