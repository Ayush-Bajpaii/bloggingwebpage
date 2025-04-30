import React, { useState, useContext } from 'react';
import AnimationWrapper from '../common/page-animation';
import InputBox from '../components/input.component';
import { Toaster, toast } from 'react-hot-toast';
import axios from 'axios';
import { UserContext } from '../App';
import { useNavigate, Link } from 'react-router-dom';

const ForgotPassword = () => {
    const { userAuth } = useContext(UserContext);
    const [email, setEmail] = useState(userAuth?.personal_info?.email || '');
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!email) {
            return toast.error("Enter Email");
        }
        if (!emailRegex.test(email)) {
            return toast.error("Invalid Email");
        }
        try {
            const response = await axios.post(import.meta.env.VITE_SERVER_DOMAIN + '/forgot-password', { email });
            toast.success(response.data.message);
            localStorage.setItem('forgotPasswordEmail', email);
            navigate('/verify-otp');
        } catch (err) {
            toast.error(err.response?.data?.error || 'Failed to send OTP');
        }
    };

    return (
        <AnimationWrapper>
            <section className="h-cover flex items-center justify-center">
                <Toaster />
                <form className="w-[80%] max-w-[400px]" onSubmit={handleSubmit}>
                    <h1 className="text-4xl font-gelasio capitalize text-center mb-24">
                        Forgot Password
                    </h1>
                    <InputBox
                        name="email"
                        type="email"
                        placeholder="E-mail"
                        icon="fi-br-envelope-dot"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                    />
                    <button className="btn-dark center mt-14" type="submit">
                        Send OTP
                    </button>
                    <p className="mt-6 text-dark-grey text-xl text-center">
                        Back to{' '}
                        <Link to="/signin" className="underline text-black text-xl ml-1">
                            Sign In
                        </Link>
                    </p>
                </form>
            </section>
        </AnimationWrapper>
    );
};

export default ForgotPassword;