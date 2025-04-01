// firebase.jsx
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
import { GoogleAuthProvider, getAuth, signInWithPopup } from "firebase/auth";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyC-jYPm9hixzTUjRDpvCa7IbI3vzKz8tzU",
  authDomain: "blogwebsite-79574.firebaseapp.com",
  projectId: "blogwebsite-79574",
  storageBucket: "blogwebsite-79574.firebasestorage.app",
  messagingSenderId: "174793282663",
  appId: "1:174793282663:web:65345f6b8d2e36c07bf0c2",
  measurementId: "G-TT3YMM6R2B",
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);

// Google Auth
const provider = new GoogleAuthProvider();
provider.addScope("profile email"); 
provider.setCustomParameters({
  prompt: "select_account", // Forces account picker on every sign-in
});
const auth = getAuth(app);

export const authWithGoogle = async () => {
  try {
    const result = await signInWithPopup(auth, provider);
    const user = result.user;
    const token = await user.getIdToken();
    console.log("Google ID Token:", token);
    return { ...user, access_token: token };
  } catch (err) {
    console.error("Google Auth Error:", err);
    throw err;
  }
};

export default app;