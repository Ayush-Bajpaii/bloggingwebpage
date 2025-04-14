import { useContext, useState } from "react";
import { getDay } from "../common/date";
import { UserContext } from "../App";
import {Toaster, toast } from "react-hot-toast";
import CommentField from "./comment-field.component";
import { BlogContext } from "../pages/blog.page";
import axios from "axios";

const CommentCard = ({ index,leftVal,commentData }) => {

    let { commented_by :{ personal_info: { profile_img, fullname, username : commented_by_user} },commentedAt,comment, _id,children } = commentData;

    let { blog,blog:{ comments, activity ,activity:{ total_parent_comment } ,comments : {results: commentsArr}, author :{ personal_info: { username: blog_author } } }  ,setBlog, setTotalParentCommentsLoaded} = useContext(BlogContext);
    let { userAuth:  { access_token, username } } = useContext(UserContext);

    let [ isReplying, setReplying ] = useState(false);


    let getparentIndex = () => {
        let startingPoint = index - 1;

        try{
            while(commentsArr[startingPoint].childern >= commentData.childrenLevel){
                startingPoint--;
            }
        }catch{
            startingPoint = undefined;
        }
        return startingPoint;

    }

    const removeCommentsCards = (startingPoint, isDelete = false) => {
        if(commentsArr[startingPoint]){
            while(commentsArr[startingPoint].childrenLevel > commentData.childrenLevel){
                commentsArr.splice(startingPoint, 1);
                if(!commentsArr[startingPoint]){
                    break;
                }
            }
        }

        if(isDelete){
            let parentIndex = getparentIndex();
            if(parentIndex != undefined){
                commentsArr[parentIndex].childern = commentsArr[parentIndex].children.filter(child => child != _id)

                if(!commentsArr[parentIndex].children.length){
                    commentsArr[parentIndex].isReplyLoaded = false;
                }
            }
            commentsArr.splice(index, 1);
        }

        if(!commentsArr.childrenLevel == 0 && isDelete){
            setTotalParentCommentsLoaded(prevVal => prevVal - 1);
        }

        setBlog({ ...blog, comments: { results: commentsArr }, activity:{
            ...activity, total_parent_comments: total_parent_comment - (commentData.childrenLevel == 0 && isDelete ? 1 : 0),
        } });

    }

    const loadReplies = ({ skip = 0 }) => {
        if(children.length){

            hideReplies();
            axios.post(import.meta.env.VITE_SERVER_DOMAIN + "/get-replies", {
                _id,skip
            })
            .then(({data:{replies}}) => {
                commentData.isReplyLoaded = true;
                for(let i = 0;i < replies.length;i++){
                    replies[i].childrenLevel = commentData.childrenLevel + 1;

                    commentsArr.splice(index + 1 + i + skip,0, replies[i] )
                }
                setBlog({ ...blog, comments :{ ...comments, results: commentsArr }})
            })
            .catch(err => {
                console.log(err)
            })
        }

    }

    const deleteComment = (e) => {
        e.target.setAttribute("disabled", true);

        axios.post(import.meta.env.VITE_SERVER_DOMAIN + "/delete-comment", { _id}, {
            headers:{
                'Authorization': `Bearer ${access_token}`  
            }
        })
        .then(() => {
            e.target.removeAttribute("disabled"); 
            removeCommentsCards(index + 1,true)
        })
        .catch(err => {
            console.log(err);
        })
    }


    const hideReplies = () => {
        commentData.isReplyLoaded = false;
        removeCommentsCards(index + 1)
    }

    const handleReplyClick = () => {
        
        if(!access_token){
            return toast.error("Please login to leave a comment");
        }

        setReplying(preval => !preval);
 
    }
    return (
            <div className="w-full" style={{paddingLeft:`${leftVal *10}px`}}>
                <div className="my-5 p-6 rounded-md border border-grey">
                    <div className="flex gap-3 items-center mb-8">
                        <img src={profile_img}  className="w-6 h-6 rounded-full"/>
                        <p className="line-clamp-1">{fullname} @{commented_by_user}</p>
                        <p className="min-w-fit">{getDay(commentedAt)}</p>
                    </div>
                    <p className="font-gelasio text-xl ml-3">{comment}</p>

                    <div className="flex gap-5 justify-between items-center mt-5">

                        {
                            commentData.isReplyLoaded ? 
                            <button className="text-dark-grey -2 px-3 hover:bg-grey/30 rounded-md flex items-center gap-2"
                            onClick={hideReplies}>
                               <i className="fi fi-rs-comment-dots"></i>Hide Replies
                            </button> : 
                            <button className="text-dark-grey -2 px-3 hover:bg-grey/30 rounded-md flex items-center gap-2"
                            onClick={loadReplies}
                            >
                                 <i className="fi fi-rs-comment-dots"></i>{children.length} Replies
                            </button>
                        }
                    <button 
                    onClick={handleReplyClick}
                    className="underline">Reply</button>

                    {
                        username == commented_by_user || username == blog_author ? 
                        <button className="p-2 px-3 rounded-md border border-grey hover:bg-red/30 hover:text-red flex items-center gap-2"
                            onClick={deleteComment}
                        >
                             <i className="fi fi-br-trash pointer-events-none"></i>
                        </button>
                        : ""
                    }
                    </div>

                    {
                        isReplying ? 
                        <div className="mt-8">
                            <CommentField action="reply" index={index}
                            replyingTo={_id} setReplying={setReplying}/>
                        </div> : ""
                    }
                   

                </div>

            </div>
    )
}
export default CommentCard;