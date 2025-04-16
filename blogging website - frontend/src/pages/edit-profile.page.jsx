import { useContext, useEffect, useRef, useState } from "react";
import { UserContext } from "../App";
import axios from "axios";
import { profileDataStructure } from "./profile.page";
import Loader from "../components/loader.component";
import AnimationWrapper from "../common/page-animation";
import { Toaster, toast } from "react-hot-toast";
import InputBox from "../components/input.component";
import { uploadImage } from "../common/aws";
import { storeInSession } from "../common/session";

const EditProfile = () => {

    let { userAuth, userAuth: { access_token }, setUserAuth } = useContext(UserContext);


    let bioLimit = 150;
    let profileImgEle = useRef();
    let editProfileForm = useRef()
    const [profile, setProfile] = useState(profileDataStructure);
    const [loading, setLoading] = useState(true);

    const [charactersLeft, setCharactersLeft] = useState(bioLimit);
    const [updatedProfileImg, setUpdatedProfileImg] = useState(null);

    let { personal_info: { fullname, username: profile_username, profile_img, email, bio }, social_links } = profile;



    useEffect(() => {
        if (access_token) {
            axios.post(import.meta.env.VITE_SERVER_DOMAIN + "/get-profile", { username: userAuth.username })
                .then(({ data }) => {
                    setProfile(data);
                    setLoading(false);

                })
                .catch(err => {
                    console.log(err)
                })
        }

    }, [access_token]);

    const handleCharacterChange = (e) => {
        setCharactersLeft(bioLimit - e.target.value.length)

    }

    const handleImagePreview = (e) => {
        let img = e.target.files[0];
        profileImgEle.current.src = URL.createObjectURL(img);
        setUpdatedProfileImg(img);
    }
    const handleImageUpload = (e) => {
        console.log("handleImageUpload called");

        e.preventDefault();
        if (updatedProfileImg) {
            let loadingToast = toast.loading("Uploading....")
            e.target.setAttribute("disabled", true)
            uploadImage(updatedProfileImg)
                .then(url => {
                    if (url) {
                        axios.post(import.meta.env.VITE_SERVER_DOMAIN + "/updated-profile-img", { url }, {
                            headers: {
                                'Authorization': `Bearer ${access_token}`
                            }
                        })
                            .then(({ data }) => {
                                let newUserAuth = { ...userAuth, profile_img: data.profile_img }
                                storeInSession("user", JSON.stringify(newUserAuth));
                                setUserAuth(newUserAuth);
                                setUpdatedProfileImg(null);
                                toast.dismiss(loadingToast);
                                e.target.removeAttribute("disabled")
                                toast.success("Uploaded 👍")



                            })
                            .catch(({ response }) => {
                                toast.dismiss(loadingToast);
                                e.target.removeAttribute("disabled")
                                toast.error(response.data.error)

                            })
                    }
                })
                .catch(err => {
                    console.log(err);
                })



        }
    }

    const handleSubmit = (e) => {
        e.preventDefault();
        let form = new FormData(editProfileForm.current);
        let formData = {};
        for (let [key, value] of form.entries()) {
            formData[key] = value;

        }
        let { username, bio, youtube, facebook, twitter, github, instagram, website } = formData;

        if(username.length < 3){
            return toast.error("Username should be atleast 3 letters long")
        }
        if(bio.length > bioLimit){
            return toast.error(`Bio should not be more than ${bioLimit}`)
        }
    }

    return (

        <AnimationWrapper>
            {
                loading ? <Loader /> :
                    <form ref={editProfileForm} >
                        <Toaster />
                        <h1 className="max-md:hidden">Added Profile</h1>
                        <div className="flex flex-col lg:flex-row items-start py-10 gap-8 lg:gap-10">
                            <div className="max-lg:center mb-5">
                                <label htmlFor="uploadImg" id="profileImgLabel"
                                    className="relative block w-48 h-48 bg-grey rounded-full overflow-hidden">
                                    <div className="w-full h-full justify-center items-center flex absolute top-0 left-0 text-white bg-black/50 opacity-0 hover:opacity-100 cursor-pointer">
                                        Upload Image
                                    </div>
                                    <img ref={profileImgEle} src={profile_img} />
                                </label>
                                <input type="file" id="uploadImg" accept=".jpeg, .png, .jpg" hidden onChange={handleImagePreview} />
                                <button className="btn-light mt-5 max-lg:center lg:w-full px-10"
                                    onClick={handleImageUpload}>Upload</button>
                            </div>
                            <div className="w-full">
                                <div className="grid grid-cols-1 md:grid-cols-2 md:gap-5">
                                    <div>
                                        <InputBox
                                            name="fullname"
                                            type="text"
                                            disable={true}
                                            value={fullname}
                                            icon="fi-sr-user"
                                            onChange={(e) =>
                                                setProfile((prev) => ({
                                                    ...prev,
                                                    personal_info: {
                                                        ...prev.personal_info,
                                                        fullname: e.target.value,
                                                    },
                                                }))
                                            }
                                        />
                                    </div>
                                    <div>
                                        <InputBox
                                            name="email"
                                            type="text"
                                            disable={true}
                                            value={email}
                                            icon="fi-sr-envelope"
                                            onChange={(e) =>
                                                setProfile((prev) => ({
                                                    ...prev,
                                                    personal_info: {
                                                        ...prev.personal_info,
                                                        email: e.target.value,
                                                    },
                                                }))
                                            }
                                        />

                                    </div>
                                </div>
                                <InputBox type="text" name="username" value={profile_username} placeholder="username" icon="fi-br-at"
                                    onChange={(e) =>
                                        setProfile((prev) => ({
                                            ...prev,
                                            personal_info: {
                                                ...prev.personal_info,
                                                username: e.target.value,
                                            },
                                        }))
                                    } />
                                <p className=" text-dark-grey -mt-3">Username will use to search user and visible to all users</p>
                                <textarea name="bio" maxLength={bioLimit} defaultValue={bio} className="input-box h-64 lg:h-40 resize-none leading-7 mt-5 pl-5 " placeholder="Bio" onChange={handleCharacterChange}></textarea>
                                <p className="mt-1 text-dark-grey ">{charactersLeft} Characters left</p>
                                <p className="my-6 text-dark-grey ">Add your social handle below</p>
                                <div className="md:grid md:grid-cols-2 gap-x-6  ">

                                    {
                                        Object.keys(social_links).map((key, i) => {
                                            let links = social_links[key];
                                            return <InputBox key={i}
                                                name={key}
                                                type="text" value={links}
                                                icon={"fi " + (key != 'website' ? "fi-brands-" + key : "fi-ss-globe")}
                                                placeholder="https://"
                                                onChange={(e) =>
                                                    setProfile((prev) => ({
                                                        ...prev,
                                                        social_links: {
                                                            ...prev.social_links,
                                                            [key]: e.target.value,
                                                        },
                                                    }))
                                                } />
                                        })
                                    }
                                </div>
                                <button className="btn-dark w-auto px-10" type="submit"
                                    onClick={handleSubmit}
                                >Update</button>
                            </div>

                        </div>
                    </form>
            }
        </AnimationWrapper>
    )

}
export default EditProfile;