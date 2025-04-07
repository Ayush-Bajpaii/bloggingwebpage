import { Link } from "react-router-dom";
import PageNotFoundImage from "../imgs/404.png"
import fullLogo from "../imgs/full-logo.png"

const PageNotFound = () => {
    return (

        <section className="h-cover relative p-10 flex flex-col items-center gap-20 text-center">
            <img src={PageNotFoundImage} className="select-none border-grey w-72 aspect-square object-cover rounded-full" />

            <h1 className="text-4xl font-gelasio leading-7">Page Not Found</h1>
            <p className="text-dark-grey text-xl leading-7 -mt-8">Page You are looking for does not exist.Head Back to the <Link to="/" className="text-red text-xl underline" >Home Page</Link></p>

            <div className="mt-auto">
                <img src={fullLogo} className="h-8 object-contain block mx-auto select-none"/>
                <p className="mt-5 text-dark-grey">Read Stories around the world</p>

            </div>

        </section>
    )

}
export default PageNotFound;