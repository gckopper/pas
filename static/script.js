function auth() {
    let xmlHttp = new XMLHttpRequest();
    xmlHttp.open( "GET", '/', false ); // false for synchronous request
    xmlHttp.setRequestHeader("Username", document.getElementById("name").value)
    xmlHttp.setRequestHeader("Password", document.getElementById("password").value)
    xmlHttp.setRequestHeader("OTP", document.getElementById("otp").value)
    xmlHttp.send( null );
    console.log(xmlHttp.status);
    switch (xmlHttp.status) {
        case 200:
            window.location.replace("/");
            return;
        case 401:
            alert("Wrong password and/or username and/or OTP")
            return;
        case 403:
            alert("Either you left one or more of the auth fields empty or they are no the correct size. Username and password have a maximum length of 64 characters and OTP MUST be 6 digits long")
            return;
        default:
            alert("Something went horribly wrong. Please contact the admin.")
            return;
    }
}
function show() {
    if (document.getElementById("password").type == "password") {
        document.getElementById("password").type = "text"
        document.getElementById("eye-line").style = "display:none"
    } else {
        document.getElementById("password").type = "password"
        document.getElementById("eye-line").style = "display:block"
    }
}