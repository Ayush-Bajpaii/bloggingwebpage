import Embed from "@editorjs/embed";
import List from "@editorjs/list";
import Image from "@editorjs/image";
import Header from "@editorjs/header";
import Quote from "@editorjs/quote";
import Marker from "@editorjs/marker";
import InlineCode from "@editorjs/inline-code";
import { uploadImage } from "../common/aws";
 


const uploadImgeByFile = (e) => {
     return uploadImage(e).then(url => {
        if(url){
            return {
                success:1,
                file: {url}
            }
        }
     })
}

const uploadImageByURL = (e) => {
    let link = new Promise((resolve, reject) =>  {
        if (typeof e === "string" && e.startsWith("http")) {
            resolve(e);
        } else {
            reject("Invalid URL");
        }
    })
    return link.then(url => {
        return {
            success: 1,
            file: { url }
        }
    }).catch(err => {
        return {
            success: 0,
            message: err
        }
    })
}

export const tools = {
    embed:Embed,
    list:{
        class:List,
        inlineToolbar:true
    },
    image:{
        class:Image,
        config:{
            uploader:{
                uploadByUrl: uploadImageByURL,
                uploadByFile: uploadImgeByFile
            }
           
            
        }
    },

    header:{
        class:Header,
        config:{
            placeholder:"Type heading...",
            levels:[2,3],
            defaultLevel:2
        }
    },
    quote: {
        class:Quote,
        inlineToolbar:true
    },
    marker:Marker,
    inlineCode:InlineCode

} 
