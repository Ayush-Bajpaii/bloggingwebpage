import React, { useState } from 'react';
import AnimationWrapper from '../common/page-animation';
import InputBox from '../components/input.component';
import { Toaster, toast } from 'react-hot-toast';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';

const VerifyOTP = () => {
    const [otp, setOtp] = useState('');
    const email = localStorage.getItem('forgotPasswordEmail') || '';
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!otp) {
            return toast.error("Please enter the OTP");
        }
        try {
            const response = await axios.post(import.meta.env.VITE_SERVER_DOMAIN + '/verify-otp', { email, otp });
            toast.success(response.data.message);
            navigate('/reset-password');
        } catch (err) {
            toast.error(err.response?.data?.error || 'Failed to verify OTP');
        }
    };

    const handleResend = async () => {
        try {
            const response = await axios.post(import.meta.env.VITE_SERVER_DOMAIN + '/forgot-password', { email });
            toast.success(response.data.message);
        } catch (err) {
            toast.error(err.response?.data?.error || 'Failed to resend OTP');
        }
    };

    return (
        <AnimationWrapper>
            <section className="h-cover flex items-center justify-center">
                <Toaster />
                <form className="w-[80%] max-w-[400px]" onSubmit={handleSubmit}>
                    <h1 className="text-4xl font-gelasio capitalize text-center mb-24">
                        Verify OTP
                    </h1>
                    <p className="text-dark-grey text-center mb-6">
                        Enter the OTP sent to {email}
                    </p>
                    <InputBox
                        name="otp"
                        type="text"
                        placeholder="Enter OTP"
                        icon="fi-rr-key"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value)}
                    />
                    <button className="btn-dark center mt-5 mb-5" type="submit">
                        Verify OTP
                    </button>
                    <button
                        type="button"
                        onClick={handleResend}
                        className="btn-light center mt-2 mb-5 text-sm"
                    >
                        Resend OTP
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

export default VerifyOTP;