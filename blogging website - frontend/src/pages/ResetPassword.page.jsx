import React, { useState } from 'react';
import AnimationWrapper from '../common/page-animation';
import InputBox from '../components/input.component';
import { Toaster, toast } from 'react-hot-toast';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';

const ResetPassword = () => {
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const email = localStorage.getItem('forgotPasswordEmail') || '';
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;
        if (!newPassword) {
            return toast.error("Enter New Password");
        }
        if (!passwordRegex.test(newPassword)) {
            return toast.error('Password must be 6-20 characters with a number, lowercase, and uppercase letter');
        }
        if (newPassword !== confirmPassword) {
            return toast.error('Passwords do not match');
        }
        try {
            const response = await axios.post(import.meta.env.VITE_SERVER_DOMAIN + '/reset-password', {
                email,
                newPassword,
                confirmPassword,
            });
            toast.success(response.data.message);
            localStorage.removeItem('forgotPasswordEmail');
            setTimeout(() => navigate('/signin'), 2000);
        } catch (err) {
            toast.error(err.response?.data?.error || 'Failed to reset password');
        }
    };

    return (
        <AnimationWrapper>
            <section className="h-cover flex items-center justify-center">
                <Toaster />
                <form className="w-[80%] max-w-[400px]" onSubmit={handleSubmit}>
                    <h1 className="text-4xl font-gelasio capitalize text-center mb-24">
                        Reset Password
                    </h1>
                    <InputBox
                        name="newPassword"
                        type="password"
                        placeholder="New Password"
                        icon="fi-ss-lock"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                    />
                    <InputBox
                        name="confirmPassword"
                        type="password"
                        placeholder="Confirm Password"
                        icon="fi-ss-lock"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                    <button className="btn-dark center mt-14" type="submit">
                        Reset Password
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

export default ResetPassword;