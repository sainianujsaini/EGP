import express from "express";
import {dirname} from 'path';
import { fileURLToPath } from "url";
import pg from 'pg'
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from 'dotenv';
const __dirname = dirname(fileURLToPath(import.meta.url));
env.config();
const app = express();
const port = 4000;

function generateApplicationNumber() {
    // Get current date and time
    const now = new Date();
  
    // Extract components: Year, Month, Day, Hour, Minute, Second, Millisecond
    const year = now.getFullYear().toString(); // Full year, e.g., "2024"
    const month = (now.getMonth() + 1).toString().padStart(2, '0'); // Months are 0-based in JS, pad with 0 if single digit
    const day = now.getDate().toString().padStart(2, '0'); // Pad with 0 if single digit
    const hour = now.getHours().toString().padStart(2, '0'); // Pad with 0 if single digit
    const minute = now.getMinutes().toString().padStart(2, '0'); // Pad with 0 if single digit
    const second = now.getSeconds().toString().padStart(2, '0'); // Pad with 0 if single digit
    const millisecond = now.getMilliseconds().toString().padStart(3, '0'); // Pad with 0 if fewer than 3 digits
  
    // Generate a random number between 100 and 999
    const randomNum = Math.floor(100 + Math.random() * 900);
  
    // Combine components to form a unique application number
    const applicationNumber = `${year}${month}${day}${hour}${minute}${second}${millisecond}${randomNum}`;
  
    return applicationNumber;
  }


app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(express.json());

app.use(session({
    secret : process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized : true,
    cookie : {maxAge : 1000*60*60*24}
}));
app.use(passport.initialize());
app.use(passport.session());
app.set('view engine', 'ejs');
const saltRounds = 10;
const db = new pg.Client({
    user: process.env.POSTGRES_USER,
    host: process.env.POSTGRES_HOST,
    database: process.env.POSTGRES_DATABASE,
    password: process.env.POSTGRES_PASSWORD,
    port: process.env.POSTGRES_PORT,
  });
  db.connect();
app.get("/u/services" ,async (req , res)=>{
    try{
        const result = await db.query("select * from services_details");
        console.log(result.rows);
        res.render("user/applyservices" , {services : result.rows});
    }
    catch(e){console.log("Error fetching service data");}
});
app.get("/staff/services" ,async (req , res)=>{
    if(req.isAuthenticated() && (req.user.account_type == "staff" || req.user.account_type == "officer")){
        try{
            const result = await db.query("select * from services_details");
            console.log(result.rows);
            res.render("staff/services" , {services : result.rows});
        }
        catch(e){console.log("Error fetching service data");}
    }
    else{
        res.redirect("/login");
    }
});
app.get("/u/apply/:id" , async (req , res)=>{
    if(req.isAuthenticated() && req.user.account_type == "user"){
    var id = req.params.id;
    try{
        const result = await db.query("select * from services_details where id = $1" , [id]);
        if(result.rowCount == 0){res.send("Service Not Found :(");}
        else{
            var file_name = result.rows[0].file_name;
            res.render("services/" + file_name , {service_name : result.rows[0].service_name , service_department : result.rows[0].service_department , service_detail : result.rows[0].service_detail , service_id : result.rows[0].id});
        }
    }
    catch(e){
        console.log("Error in fetching the service name from db" + e);
    }
}
else{
    res.redirect("/login");
}
}); 
app.get("/staff/services_status" , async(req, res)=>{
    if(req.isAuthenticated() && (req.user.account_type == "user" || req.user.account_type == "officer")){
    try{
        var electricity = await db.query("select * from user_service join electricity on user_service.application_no = electricity.application_no where user_service.status = 'Pending'");
        var loan = await db.query("select * from user_service join loan on user_service.application_no = loan.application_no where user_service.status = 'Pending'");
        var casteCertificate = await db.query("select * from user_service join caste_certificate on user_service.application_no = caste_certificate.application_no where user_service.status = 'Pending'");
        var voterID = await db.query("select * from user_service join voter_id on user_service.application_no = voter_id.application_no where user_service.status = 'Pending'");
        var scholarship = await db.query("select * from user_service join scholarship on user_service.application_no = scholarship.application_no where user_service.status = 'Pending'");
        var shopLicense = await db.query("select * from user_service join license on user_service.application_no = license.application_no where user_service.status = 'Pending'");
        console.log(electricity.rows);
        res.render("staff/update_service_status" , {electricity : electricity.rows , loan : loan.rows , casteCertificate : casteCertificate.rows , voterID : voterID.rows , scholarship : scholarship.rows , shopLicense : shopLicense.rows});
    }
    catch(e){
        console.log("Error occored" + e);
    }
}
else{
    res.redirect("/login");
}
});
app.get("/staff/view_service/:id", async (req, res)=>{
    if(req.isAuthenticated() && (req.user.account_type == "staff" || req.user.account_type == "officer")){
        try{
            var service_id = req.params.id;
            var result = await db.query("select service_name , service_department , creation_date , start_date , end_date  from services_details where id = $1" , [service_id]);
            var total_application = await db.query("select count(*) as total_applications from user_service where service_id = $1" , [service_id]);
            var approved_applications = await db.query("select count(*) as approved from user_service where service_id = $1 and status = 'Approved'" , [service_id]);
            var rejected_applicaitons = await db.query("select count(*) as rejected from user_service where service_id = $1 and status = 'Rejected'" , [service_id]);
            var total = total_application.rows[0].total_applications;
            var approved = approved_applications.rows[0].approved;
            var rejected = rejected_applicaitons.rows[0].rejected;
            var pending = total - approved - rejected;
        res.render("staff/services_details" , {service : result.rows[0] , total_applications : total , applications_accepted : approved , applications_rejected : rejected , applications_pending : pending});
        }
        catch(e){
            console.log(e);
        }
    }
    else{
        res.redirect("/login");
    }
});
app.post("/u/submit/:service", async (req, res) => {
    // console.log(req.isAuthenticated());
    if(req.isAuthenticated() && req.user.account_type == "user"){
        const service = req.params.service;
        var user_id = req.user.id;
        let result;
    try{
        var application_no = generateApplicationNumber();
        var service_result = await db.query("select id from services_details where service_name = $1" , [service]);
        var service_id = service_result.rows[0].id;
        var store = db.query("insert into user_service(user_id , service_id , application_no , status) values($1 , $2 , $3 , $4)" , [user_id , service_id , application_no , "Pending"]);
    if (service === "Electricity Issue Service") {
        const { first_name, last_name, phone_number, state, meter_number, issue_type, address, reason } = req.body;
        result = await db.query(
            "INSERT INTO electricity (first_name, last_name, phone_number, state, meter_number, issue_type, address, reason, submission_date , application_no , service_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9 , $10 , $11)", 
            [first_name, last_name, phone_number, state, meter_number, issue_type, address, reason, new Date().toISOString().split('T')[0] , application_no , service_id]
        );
    } else if (service === "Shop License") {
        const { first_name, last_name, phone_number, state, shop_name, shop_type, shop_address, shop_area, reason } = req.body;
        result = await db.query(
            "INSERT INTO license (first_name, last_name, phone_number, state, shop_name, shop_type, shop_address, shop_area, reason, submission_date , application_no , service_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10 , $11 , $12)", 
            [first_name, last_name, phone_number, state, shop_name, shop_type, shop_address, shop_area, reason, new Date().toISOString().split('T')[0] , application_no , service_id]
        );
    } else if (service === "Loan Service") {
        const { first_name, last_name, phone_number, state, income, property_amount, loan_amount, reason } = req.body;
        result = await db.query(
            "INSERT INTO loan (first_name, last_name, phone_number, state, income, property_amount, loan_amount, reason, submission_date , application_no , service_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9 , $10 , $11)", 
            [first_name, last_name, phone_number, state, income, property_amount, loan_amount, reason, new Date().toISOString().split('T')[0] , application_no , service_id]
        );
    } else if (service === "Scholarship Service") {
        const { first_name, last_name, phone_number, state, course_name, institute_name, academic_year, scholarship_amount, reason } = req.body;
        result = await db.query(
            "INSERT INTO scholarship (first_name, last_name, phone_number, state, course_name, institute_name, academic_year, scholarship_amount, reason, submission_date , application_no , service_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10 , $11 , $12)", 
            [first_name, last_name, phone_number, state, course_name, institute_name, academic_year, scholarship_amount, reason, new Date().toISOString().split('T')[0] , application_no , service_id]
        );
    } else if (service === "Voter ID Issue") {
        const { first_name, last_name, phone_number, state, voter_id_number, address, date_of_birth, issue_type, reason } = req.body;
        result = await db.query(
            "INSERT INTO voter_id (first_name, last_name, phone_number, state, voter_id_number, address, date_of_birth, issue_type, reason, submission_date , application_no , service_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10 , $11 , $12)", 
            [first_name, last_name, phone_number, state, voter_id_number, address, date_of_birth, issue_type, reason, new Date().toISOString().split('T')[0] , application_no , service_id]
        );
    } else if (service === "Caste Certificate Issue") {
        const { first_name, last_name, phone_number, state, caste, father_name, mother_name, date_of_birth, address, reason } = req.body;
        result = await db.query(
            "INSERT INTO caste_certificate (first_name, last_name, phone_number, state, caste, father_name, mother_name, date_of_birth, address, reason, submission_date , application_no , service_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11 , $12 , $13)", 
            [first_name, last_name, phone_number, state, caste, father_name, mother_name, date_of_birth, address, reason, new Date().toISOString().split('T')[0] , application_no , service_id]
        );
    } else {
        res.status(400).send("Unknown service requested");
    }
    res.send("Saved");
}
catch(e){
    console.log(e);
    res.status(500).send("There was an error processing your request.");
}
    }
    else{
        res.redirect("/login");
    }
});




app.get("/" , (req,res)=>{
    res.redirect("/u/services");
});

app.get("/login" ,(req , res)=>{
    res.sendFile(__dirname + "/public/html/login.html");
})
app.get("/register" , (req , res)=>{
    res.sendFile(__dirname + "/public/html/register.html");
});
app.post("/register" ,async (req , res)=>{
    const {username , email , password , confirmpassword} = req.body;
    try{
        var stored = await db.query("select * from account_details where email = $1" , [email]);
        if(stored.rowCount != 0){
            res.status(400).send("User already exists, try logging in");
        }
        else{
            if(password !== confirmpassword){
                res.status(400).send("Passwords do not match");
            }
            else{
                try{
                    console.log(new Date().toISOString());
                    const currDate = new Date().toISOString().split('T')[0];
                    bcrypt.hash(password , saltRounds , async(err , hash)=>{
                        if(err){
                            console.log("Error in hashing password");
                        }
                        else{
                            console.log(hash);
                            console.log(currDate);
                            var storing = await db.query("insert into account_details(name , email , password , creation_date) values($1 , $2 , $3 , $4) returning *" , [username , email , hash , currDate]);
                            const user = storing.rows[0];
                            req.login(user , (err)=>{
                                res.redirect("/secrets");
                            })
                        }
                    });
                    
                }
                catch(err){
                    res.status(500).send("Error checking user existence");
                }
            }
        }
    }
    catch(err){
        console.log(err);
    }
})

// app.post("/login" , async(req , res)=>{
//     try{
//         var {accountType , email , password} = req.body;
//         console.log(req.body);
//         var stored = await db.query("select * from account_details where email = $1 and account_type = $2" , [email , accountType]);
//         if(stored.rowCount == 0){
//             res.status(400).send("User doesn't exist!");
//         }
//         else{
//             const user = stored.rows[0];
//             bcrypt.compare(password , user.password , (err , valid)=>{
//                 if(err){
//                     console.log("Error comparing passwords");
//                 }
//                 else{
//                     if(valid){
//                         res.status(400).send("User Found :)");
//                     }
//                     else{
//                         res.status(400).send("Incorrect password");
//                     }
//                 }
//             })
//         }
//     }
//     catch(e){
//         console.log(e);
//     }
// });
app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login"
}));
app.get("/secrets" , (req , res)=>{
    if(req.isAuthenticated()){
        res.sendFile(__dirname + "/public/html/secret.html");
    }
    else{
        res.redirect("/login");
    }
})

app.get("/logout", (req, res) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/login");
    });
  });
  app.post('/update-status', async (req, res) => {
    console.log(req.params);
    const { applicationId, status } = req.body;
    try{
    var result = await db.query("update user_service set status = $1 where application_no = $2" , [status , applicationId]);
    console.log("Data updated to " + status);
    res.json({success : true});
    }
    catch(e){
        console.log("There is error" + e);
        res.json({success : false});
    }
  });

app.get("/auth/google" , passport.authenticate("google" , {
    scope : ["profile" , "email"]
}));

app.get("/auth/google/secrets" , passport.authenticate("google" , {
    successRedirect : "/secrets",
    failureRedirect : "/login"
}));

passport.use("local" , new Strategy(
    { usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    },
    async function verify(req , email , password , callback){
    try{
        console.log("I am called");
        // console.log(req.body);
        const accountType = req.body.accountType;
        const result = await db.query("select * from account_details where email = $1 and account_type = $2" , [email , accountType]);
        if(result.rowCount > 0){
            const user = result.rows[0];
            if(accountType == "staff"){
                var storedPassword = user.password;
                if(password === storedPassword){
                    callback(null , user);
                }
                else{
                    callback(null , false);
                }
            }
            else if(accountType == "officer"){
                var storedPassword = user.password;
                if(password === storedPassword){
                    callback(null , user);
                }
                else{
                    callback(null , false);
                }
            }
            else{
            const storedHashedPassword = user.password;
            bcrypt.compare(password , storedHashedPassword , (err , result)=>{
                if(err){
                    callback(err);
                }
                else{
                    if(result){
                        callback(null , user);
                    }
                    else{
                        
                        callback(null , false);
                    }
                }
            });
        }
        }
        else{
            callback("User not found");
        }
    }
    catch(err){
        console.log(err);
    }
}));

// Google OAuth 

passport.use("google" , new GoogleStrategy({                                   // Give a name to it here we have given it google
    clientID : process.env.GOOGLE_CLIENT_ID,                                     // Your google project ID created
    clientSecret : process.env.GOOGLE_CLIENT_SECRET,                             // Your google project secret created
    callbackURL : "http://localhost:4000/auth/google/secrets",                   // Where it will redirect to after success
    userProfileURL : "https://www.googleapis.com/oauth2/v3/userinfo"             // used to fetch the user info as access token
    } , async(accessToken, refreshToken, profile, callback)=>{             // Callback function which will called once the process succeeds.
          console.log(profile);
          try{
            const currDate = new Date().toISOString().split('T')[0];
            const result = await db.query("select * from account_details where email = $1 and account_type = $2" , [profile.email , "user"]);
            if(result.rows.length == 0){
              const newUser = await db.query("insert into account_details(name , email , password , account_type , creation_date) values($1,$2,$3,$4,$5)" , [profile.displayName, profile.email, "google", "user" , currDate]);
              callback(null , newUser.rows[0]);
            }
            else{
              // Already exists 
              callback(null , result.rows[0]);
            }
          }
          catch(err){
            callback(err);
          }
        }
  ));


passport.serializeUser((user , callback)=>{
    callback(null , user);
  });
  passport.deserializeUser((user , callback)=>{
    callback(null , user);
  });
app.listen(port,()=>{
    console.log("Server is up and running on port " + port);
});













/*
    While clicking the sign with google button with the form get automatically filled was causing the form submission triggered using local strategy // It means that the form was getting submitted and not google authentication was done
    To resolve this make the button type from default/submit to button beacause the button's default type is submit and it might cause form submission even if the button is outsid the form. Second way is to use event.preventDefault();
    windows.location.href = '/something' can be used to redirect using JS.
*/