import { useContext, useState, useEffect } from "react";
import AnimationWrapper from "../common/page-animation";
import InputBox from "../components/input.component";
import googleIcon from "../imgs/google.png";
import { Link, Navigate } from "react-router-dom";
import { Toaster, toast } from "react-hot-toast";
import axios from "axios";
import { storeInSession } from "../common/session";
import { UserContext } from "../App";
import { authWithGoogle } from "../common/firebase";

const UserAuthForm = ({ type }) => {
    let { userAuth: { access_token }, setUserAuth } = useContext(UserContext);
    const [otpSent, setOtpSent] = useState(false);
    const [otp, setOtp] = useState("");
    const [formData, setFormData] = useState({
        fullname: "",
        email: "",
        password: "",
        confirmPassword: ""
    });

    useEffect(() => {
        setFormData({
            fullname: "",
            email: "",
            password: "",
            confirmPassword: ""
        });
        setOtpSent(false);
        setOtp("");
    }, [type]);

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const userAuthThroughServer = (serverRoute, formData) => {
        axios
            .post(import.meta.env.VITE_SERVER_DOMAIN + serverRoute, formData)
            .then(({ data }) => {
                storeInSession("user", JSON.stringify(data));
                setUserAuth(data);
                toast.success(type === "sign-in" ? "Signin successful!" : "Signup successful!");
            })
            .catch((error) => {
                const errorMessage = error.response?.data?.error || "An unknown error has occurred";
                toast.error(errorMessage);
            });
    };

    const handleRequestOtp = async (e) => {
        e.preventDefault();
        let emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

        const { fullname, email, password, confirmPassword } = formData;

        if (type === "sign-up") {
            if (fullname.length < 3) {
                return toast.error("Fullname must be at least 3 letters long");
            }
            if (!email) {
                return toast.error("Enter Email");
            }
            if (!emailRegex.test(email)) {
                return toast.error("Invalid Email");
            }
            if (!passwordRegex.test(password)) {
                return toast.error(
                    "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letter"
                );
            }
            if (password !== confirmPassword) {
                return toast.error("Passwords do not match");
            }

            axios
                .post(import.meta.env.VITE_SERVER_DOMAIN + "/request-otp", { email, type })
                .then(({ data }) => {
                    toast.success(data.message);
                    setOtpSent(true);
                })
                .catch((err) => {
                    toast.error(err.response?.data.error || "Failed to send OTP");
                });
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        let serverRoute = type === "sign-in" ? "/signin" : "/signup";
        let emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

        const { email, password } = formData;

        if (type === "sign-in") {
            if (!email) {
                return toast.error("Enter Email");
            }
            if (!emailRegex.test(email)) {
                return toast.error("Invalid Email");
            }
            // if (!passwordRegex.test(password)) {
            //     return toast.error(
            //         "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letter"
            //     );
            // }
        }

        if (type === "sign-up") {
            if (!otp) {
                return toast.error("Please enter the OTP");
            }
        }

        const dataToSend = type === "sign-up" ? { ...formData, otp } : formData;
        userAuthThroughServer(serverRoute, dataToSend);
    };

    const handleGoogleAuth = (e) => {
        e.preventDefault();
        authWithGoogle()
            .then((user) => {
                let serverRoute = "/google-auth";
                let formData = {
                    access_token: user.access_token
                };
                userAuthThroughServer(serverRoute, formData);
            })
            .catch((err) => {
                toast.error("Trouble logging in through Google");
                return console.log(err);
            });
    };

    return (
        access_token ? (
            <Navigate to="/" />
        ) : (
            <AnimationWrapper keyValue={type}>
                <section className="h-cover flex items-center justify-center">
                    <Toaster />
                    <form className="w-[80%] max-w-[400px]" onSubmit={handleSubmit}>
                        <h1 className="text-4xl font-gelasio capitalize text-center mb-24">
                            {type === "sign-in" ? "Welcome back" : "Join us Today"}
                        </h1>

                        {type === "sign-in" ? (
                            <>
                                <InputBox
                                    name="email"
                                    type="email"
                                    placeholder="E-mail"
                                    icon="fi-br-envelope-dot"
                                    value={formData.email}
                                    onChange={handleChange}
                                />
                                <InputBox
                                    name="password"
                                    type="password"
                                    placeholder="Password"
                                    icon="fi-ss-lock"
                                    value={formData.password}
                                    onChange={handleChange}
                                />
                                <p className="text-dark-grey text-sm text-right mt-2">
                                    <Link to="/forgot-password" className="underline">
                                        Forgot Password?
                                    </Link>
                                </p>
                                <button className="btn-dark center mt-14" type="submit">
                                    Sign In
                                </button>
                            </>
                        ) : (
                            <>
                                {!otpSent ? (
                                    <>
                                        <InputBox
                                            name="fullname"
                                            type="text"
                                            placeholder="Full Name"
                                            icon="fi-ss-user-pen"
                                            value={formData.fullname}
                                            onChange={handleChange}
                                        />
                                        <InputBox
                                            name="password"
                                            type="password"
                                            placeholder="Password"
                                            icon="fi-ss-lock"
                                            value={formData.password}
                                            onChange={handleChange}
                                        />
                                        <InputBox
                                            name="confirmPassword"
                                            type="password"
                                            placeholder="Confirm Password"
                                            icon="fi-ss-lock"
                                            value={formData.confirmPassword}
                                            onChange={handleChange}
                                        />
                                        <InputBox
                                            name="email"
                                            type="email"
                                            placeholder="E-mail"
                                            icon="fi-br-envelope-dot"
                                            value={formData.email}
                                            onChange={handleChange}
                                        />
                                        <button
                                            type="button"
                                            onClick={handleRequestOtp}
                                            className="btn-dark center mt-14"
                                        >
                                            Sign Up
                                        </button>
                                    </>
                                ) : (
                                    <>
                                        <InputBox
                                            name="otp"
                                            type="text"
                                            placeholder="Enter OTP"
                                            icon="fi-rr-key"
                                            value={otp}
                                            onChange={(e) => setOtp(e.target.value)}
                                        />
                                        <button
                                            type="submit"
                                            className="btn-dark center mt-5 mb-5"
                                        >
                                            Proceed
                                        </button>
                                        <button
                                            type="button"
                                            onClick={handleRequestOtp}
                                            className="btn-light center mt-2 mb-5 text-sm"
                                        >
                                            Resend OTP
                                        </button>
                                    </>
                                )}
                            </>
                        )}

                        <div className="relative w-full flex items-center gap-2 my-10 opacity-10 uppercase text-black font-bold">
                            <hr className="w-1/2 border-black" />
                            <p>or</p>
                            <hr className="w-1/2 border-black" />
                        </div>

                        <button
                            className="btn-dark flex items-center justify-center gap-4 w-[90%] center"
                            onClick={handleGoogleAuth}
                        >
                            <img src={googleIcon} className="w-5" alt="Google Icon" />
                            Continue with Google
                        </button>

                        {type === "sign-in" ? (
                            <p className="mt-6 text-dark-grey text-xl text-center">
                                Don't have an account?
                                <Link to="/signup" className="underline text-black text-xl ml-1">
                                    Join us Today
                                </Link>
                            </p>
                        ) : (
                            <p className="mt-6 text-dark-grey text-xl text-center">
                                Already a member?
                                <Link to="/signin" className="underline text-black text-xl ml-1">
                                    Sign in here
                                </Link>
                            </p>
                        )}
                    </form>
                </section>
            </AnimationWrapper>
        )
    );
};

export default UserAuthForm;