import { useState } from "react";

const InputBox = ({ name, type, id, value, placeholder, icon, onChange }) => {
    const [passwordVisible, setPasswordVisible] = useState(false);

    return (
        <div className="relative w-[100%] mb-4">
            <input
                name={name}
                type={type === "password" ? (passwordVisible ? "text" : "password") : type}
                placeholder={placeholder}
                {...(value !== undefined && onChange ? { value } : {})}
                onChange={onChange}
                id={id}
                className="input-box"
                autoComplete={type === "password" ? "new-password" : "off"}
            />

            <i className={`fi ${icon} input-icon`}></i>

            {type === "password" && (
                <i
                    className={`fi ${passwordVisible ? "fi-sr-eye" : "fi-sr-eye-crossed"} input-icon left-[auto] right-4 cursor-pointer`}
                    onClick={() => setPasswordVisible(currentVal => !currentVal)}
                ></i>
            )}
        </div>
    );
};

export default InputBox;