var createError = require('http-errors');
var express = require('express');
const session = require('express-session');
var MongoDBStore = require('connect-mongodb-session')(session);
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const axios = require('axios');
const fs = require('fs');
const multer = require("multer");
const https = require('https');


/*var crypto = require('crypto');
var assert = require('assert');
var algorithm = 'aes-256-gcm'; // or any other algorithm supported by OpenSSL
var key = crypto.randomBytes(32).toString('base64');
var iv = crypto.randomBytes(12).toString('base64');*/





var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

//var indexRouter = require('./routes/index');
//var usersRouter = require('./routes/users');

// where images uploaded to the server will be stored
const upload = multer({
  dest: "./public/images"
  // you might also want to set some limits: https://github.com/expressjs/multer#limits
});

/*const getContent = async url => {
  // create a browser context inside the main Chromium process
  const browserContext = browserless.createContext()
  const promise = getHTML(url, { getBrowserless: () => browserContext })
  // close browser resources before return the result
  promise.then(() => browserContext).then(browser => browser.destroyContext())
  return promise
}*/




const app = express(),
            bodyParser = require("body-parser");
dotenv.config();

const MONGOURL = process.env.MONGO_URL;

const {List, Entry, ListSchema} = require("./models/list");
const User = require("./models/user");
const { exit } = require('process');

// storage for sessions in MongoDB
var store = new MongoDBStore({
  uri: MONGOURL,
  collection: 'sessions'
});


app.use(express.static(
    path.join(__dirname,"./dist")));


// view engine setup
//app.set('views', path.join(__dirname, 'views'));
//app.set('view engine', 'jade');




app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
//app.use(express.static(path.join(__dirname, 'public')));
//the following lines are for making images and entryImages accessable from the URL.For Ex. I can now get an image from http://localhost:8080/Bob.png
app.use(express.static(path.join(__dirname, 'public', 'images')));
app.use(express.static(path.join(__dirname, 'public', 'images', 'entryImages')));
app.use(express.static(path.join(__dirname,"./dist")));
app.use(express.static(path.join(__dirname,"./dist", 'assets')));
// don't recall the specifics, but these options for for accepting cookies only from client for the listed methods? 
const corsOptions ={
  origin: true,//origin:'http://localhost:5173', 
  credentials:true,            //access-control-allow-credentials:true
  optionSuccessStatus:200,
  methods:['GET','POST','PUT','DELETE'],


}

app.use(cors(corsOptions));
//app.options('*', cors(corsOptions));
//setting the attributes for my session. the cookie controls how long it will exist and its type of security
app.use(session({
  secret: '18306739674483',
  resave: false,
  saveUninitialized: false,
  store:store,
  cookie: {
      secure: false,
      // Enable only for HTTPS
      httpOnly: false,
      maxAge:1000*60*60*24*7
      // Prevent client-side access to cookies
      //sameSite: 'none'
      // Mitigate CSRF attacks
  }
}));

// again, not sure of the specifics, but I believe this is middlewar that is passed to every subsequent route. It controls what is allowed to be done.
app.use(function(req, res, next) {

  res.header('Access-Control-Allow-Credentials', true);
  res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE');
  res.header("Access-Control-Allow-Origin", 'http://localhost:5173', 'http://localhost:4173', 'https://wishlist-5uhp.onrender.com');
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  next();
  });

  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({extended: true}));
//app.use('/', indexRouter);
//app.use('/users', usersRouter);

mongoose.connect(MONGOURL).then(()=> {
  console.log("DB connected");
})

// download the image and save to /images
let download = function (url, dest, cb) {
  let file = fs.createWriteStream(dest);
  let request = https
      .get(url, function (response) {
          response.pipe(file);
          file.on('finish', function () {
              file.close(cb);
          });
      })
      .on('error', function (err) {
          fs.unlink(dest); // Delete the file async if there is an error
          if (cb) cb(err.message);
      });

  request.on('error', function (err) {
      console.log(err);
  });
};

//mongoose.connect.prototype.dropCollection('8\u{5}\u{FFFD}q\u{FFFD}\u{14}\u{FFFD}\u{18}\u{5}:\u{FFFD}y\u{1B}t\u{FFFD}\u{E}\u{FFFD}a\u{FFFD}\u{FFFD}:M\u{2}');

app.listen(process.env.PORT || '8080', () => {
  console.log('server listening on port 8080')
  
})

app.get('/', (req,res) => {
  res.sendFile(path.join(__dirname, 'dist/index.html'));
});

app.get("/list", (req,res) => {
  res.sendFile(path.join(__dirname, './dist/index.html'));
});

app.get("/:userID/list/:listID", (req,res) => {
  res.sendFile(path.join(__dirname, './dist/index.html'));
});

app.get("/:userID/list/:listID/share", (req,res) => {
  res.sendFile(path.join(__dirname, './dist/index.html'));
});
app.get("/list/:userID/:listID/entry/:entryID", async(req,res) => {
  res.sendFile(path.join(__dirname, './dist/index.html'));
})

app.post("/login", async(req,res) => {
  //console.log(req.body.codeResponse);

  console.log("Contacting Google....");
              const response = await axios
                  .get(`https://www.googleapis.com/oauth2/v1/userinfo?access_token=${req.body.codeResponse.access_token}`, {
                      headers: {
                          Authorization: `Bearer ${req.body.codeResponse.access_token}`,
                          Accept: 'application/json'
                      }
                  })

                  //let Collection = mongoose.model(response.data.email, ListSchema, response.data.email);

                  if(response.status == 200) {
                    req.session.user = response.data;
                    
                    //console.log(req.session.user)
                  let user = await User.findOne({email: response.data.email}).exec();
                  if (!user) {
                    let newUser = new User({
                      email: response.data.email
                    })
                    
                  

                    await newUser.save();
                    user = await User.findOne({email: req.session.user.email}).exec();
                    
                    mongoose.model( user._id.valueOf(), ListSchema, user._id.valueOf());
                    console.log("New User Saved");
                  }

                  req.session.userID = user._id.valueOf();
                  console.log("UserID: " + req.session.userID);

                  
                  console.log(req.session.user);

                 /* let collections = await mongoose.connection.listCollections();
                    
                    for (let i = 0; i < collections.length; ++i) {
                      if (collections[i].name == req.session.userID) {
                        console.log("Collection Exists for current user")
                        break;
                      }
                      else if (i == collections.length - 1) {
                        console.log("Collection not found for current user, creation in progress...")
                        mongoose.model( req.session.userID, ListSchema, req.session.userID);
                      }
                    }*/
                      
                    res.status(200).json({
                      username: req.session.user.name,
                      picture: req.session.user.picture,
                      userID: req.session.userID,
                    });
              
              }
  
})
// here we destroy the session in the database. Local session cookie and profile info will be deleted by the front end. I could not find a way to delete all at once.
app.post("/logout", async(req,res) => {

  req.session.destroy();
  //req.logout();
  //let response;

  res.send('Logged Out');
  
  //response = await Session.findById(req.sessionID);
  


}
)
app.get("/pullData", async(req,res)=> {
  console.log(req.session.id);
  //let userList = mongoose.model(req.session.user.email, new Schema({}), req.session.user.email);

  if (!req.session.userID) {
    console.log("No user ID present...redirecting to front end")
    res.json("Session Overwrite Bug");
  }
  else {
  //response = await userList.find().exec();
  
    console.log("user found")
      let response = mongoose.model(req.session.userID, ListSchema, req.session.userID);
      response = await response.find().exec();

      //encrypt user email. this is going to be stored in url and used for sharing list. You need the user's email to find the list, but the email can only be retrieve from logging in. Obviously if someone else is trying to view it they cannot do this, but we also encrypt it to keep it secure.
      //var text = req.session.user.email;
      
      /*var cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'base64'), 
        Buffer.from(iv, 'base64'));  

      var cipherText = cipher.update(text, 'utf8', 'base64');
      cipherText += cipher.final('base64');
      const tag = cipher.getAuthTag()*/
     
        res.json(response);
    
  }
  }
)


app.post("/pullList", async(req,res)=> {
  //console.log(req.body.listID);
  let response;

  /*let decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'base64'),
      Buffer.from(iv, 'base64'));
    
    decipher.setAuthTag(Buffer.from(req.body.tag, 'base64'));
    let plaintext = decipher.update(req.body.cipher, 'base64', 'utf8');
    plaintext += decipher.final('utf8');
    console.log(plaintext)*/

  if(!req.session.user || req.session.userID != req.body.userID) {
    
    response = mongoose.model(req.body.userID, ListSchema, req.body.userID,);
    response = await response.findById(req.body.listID).exec();
    //console.log(req.session.user);

 
    res.json([response,"Not owner of list"]);
  }

  else {
  
    response = mongoose.model(req.session.userID, ListSchema, req.session.userID);
    response = await response.findById(req.body.listID).exec();
    console.log(response);
    res.json([response, "Owner"]);
  
  
    /*
    if(req.body.cipher) {
      //pass encrypted email through URL always and then check if current user email matches it. If not, find list with cipher and return it
      // with some value that lets it know to navigate to share view with list data
      response = mongoose.model(req.session.user.email, ListSchema, req.session.user.email);
      response = await response.findById(req.body.listID).exec();
      console.log(response);
    }
    else {
      var text = req.
      var cipher = crypto.createCipher(algorithm, key);  
      var encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');

    }*/
 
  
  }
  }     
)




app.post("/createList",  upload.single("thumbnail"), async(req,res)=> {
  //console.log(req.body);
  let userList = mongoose.model(req.session.userID, ListSchema, req.session.userID);
  //console.log(userList);
  let list = new userList( {
      name:req.body.name,
      description: req.body.description,
      entries:[],
    })
  //console.log(req.file)
  //console.log("File: " + req.file);
  if (req.file) {
  const tempPath = req.file.path;
  const targetPath = `/server/public/images/${list.id}.png`;
  if (req.file.mimetype !== "image/png" && req.file.mimetype !== "image/jpeg") {
    fs.unlink(tempPath, (err) => {
      if (err) throw err //handle your error the way you want to;
      //console.log('File was deleted');//or else the file will be deleted
        });
    res.json({
      error: "Image must be a .png or .jpg"
    });
    
  }
  else {
    fs.rename(tempPath, targetPath, err => {
      //add error check, prompt user for correct file if incorrect?
      //if (err) return handleError(err, res);

        
        
    });
  }
  list.thumbnail = "/" + list.id + ".png";
}

else {
  list.thumbnail = "default"
}


  

  try {
    await list.save()
    console.log(list._id)
    res.json(list._id);
    
} catch(error) {
    console.log(error)
    res.json(error)
    }
  

}
)

app.post("/updateList",  upload.single("thumbnail"), async(req,res)=> {
  let response = mongoose.model(req.session.userID, ListSchema, req.session.userID);
  let list = await response.findById(req.body.id);
 
    list.name = req.body.name;
    list.description = req.body.description;
    list.thumbnail == "default" ? list.thumbnail = "default" : list.thumbnail = "/" + req.body.id + ".png"; 
    
  //console.log(req.file);
  if (req.file) {
  const tempPath = req.file.path;
  const targetPath = `./public/images/${req.body.id}.png`;
  if (req.file.mimetype !== "image/png" && req.file.mimetype !== "image/jpeg") {
    fs.unlink(tempPath, (err) => {
      if (err) throw err //handle your error the way you want to;
      //console.log('File was deleted');//or else the file will be deleted
        });
    res.json({
      error: "Image must be a .png or .jpg"
    });
    
  }
  else {
    fs.rename(tempPath, targetPath, err => {
      //add error check, prompt user for correct file if incorrect?
      //if (err) return handleError(err, res);

        
        
    });
  }
}
  
    
  

  console.log(req.body);
  console.log("List: " + list)
  
  
  

  try {
    await list.save()
    
    res.json("Saved");
    
} catch(error) {
    console.log(error)
    res.json(error)
    }
  

}
)
app.post("/pullEntry", async(req,res)=> {
  console.log(req.session);
  let response = mongoose.model(req.session.userID, ListSchema, req.session.userID,);
  response = await response.findById(req.body.id);
  
  response = response.entries.find((element) => element.id == req.body.entryID);

  console.log("Entry Found: " + response);
      
  
  
  if (response) {
      //console.log("Data found: " + response);
      res.json(response);

  }
  else {
    res.json("Nothing Found");
  }
  
      
  }
)

app.post("/createEntry",  upload.single("thumbnail"), async(req,res)=> {
  let entry = new Entry({
    name:req.body.name,
    url: req.body.url,
    thumbnailURL: req.body.thumbnail
  })
  
  // use as: download(url, destination, callback)
//let url = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRD9IqgMwOb2apkK3hAIvL4QR3g44v2bFbb5w&s";
download(req.body.thumbnail, `/server/public/images/entryImages/${entry.id}.png`, function (err) {
  if (err) {
      console.log(err);
  } else {
      console.log('done');
  }
});

  /*console.log(req.file);
  if (req.file) {
  const tempPath = req.file.path;
  const targetPath = `/home/adrian/WebProjects/NodeReact/wS/server/public/images/${req.file.originalname}`;
  if (req.file.mimetype !== "image/png" && req.file.mimetype !== "image/jpeg") {
    fs.unlink(tempPath, (err) => {
      if (err) throw err //handle your error the way you want to;
      //console.log('File was deleted');//or else the file will be deleted
        });
    res.json({
      error: "Image must be a .png or .jpg"
    });
    
  }
  else {
    fs.rename(tempPath, targetPath, err => {
      //add error check, prompt user for correct file if incorrect?
      //if (err) return handleError(err, res);

        
        
    });
  }
}
    */
  //console.log(req.body);
  entry.thumbnail = "/" + entry.id + ".png";

 
  let response = mongoose.model(req.session.userID, ListSchema, req.session.userID);
  response = await response.findById(req.body.id).exec();
  console.log("Entry: " + entry);
  console.log("List: " + response)
  response.entries.push(entry);


  try {
    await response.save()
    
    res.json("Saved");
    
} catch(error) {
    console.log(error)
    res.json(error)
    }
  

}
)

app.post("/editEntry",  upload.single("thumbnail"), async(req,res)=> {
  let response = mongoose.model(req.session.userID, ListSchema, req.session.userID);
  response = await response.findById(req.body.id);
  let entry = response.entries.find((element) => element.id == req.body.entryID);
  

  entry.name = req.body.name;
  entry.url = req.body.url;
  
  
  if(entry.thumbnailURL != req.body.thumbnail) {
    console.log("New Image Detected");
      // use as: download(url, destination, callback)
    //let url = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRD9IqgMwOb2apkK3hAIvL4QR3g44v2bFbb5w&s";
    download(req.body.thumbnail, `/server/public/images/entryImages/${entry.id}.png`, function (err) {
      if (err) {
          console.log(err);
      } else {
          console.log('done');
      }
    });
    entry.thumbnail = "/" + entry.id + ".png";
    entry.thumbnailURL = req.body.thumbnail;
  }

  /*console.log(req.file);
  if (req.file) {
  const tempPath = req.file.path;
  const targetPath = `/home/adrian/WebProjects/NodeReact/wS/server/public/images/${req.file.originalname}`;
  if (req.file.mimetype !== "image/png" && req.file.mimetype !== "image/jpeg") {
    fs.unlink(tempPath, (err) => {
      if (err) throw err //handle your error the way you want to;
      //console.log('File was deleted');//or else the file will be deleted
        });
    res.json({
      error: "Image must be a .png or .jpg"
    });
    
  }
  else {
    fs.rename(tempPath, targetPath, err => {
      //add error check, prompt user for correct file if incorrect?
      //if (err) return handleError(err, res);

        
        
    });
  }
}
    */
  //console.log(req.body);
  


  try {
    await response.save()
    
    res.json("Saved");
    
} catch(error) {
    console.log(error)
    res.json(error)
    }
  

}
)

app.post("/deleteEntry", async(req,res)=> {

  //console.log(req.body)
  let index;
  let response = mongoose.model(req.session.userID, ListSchema, req.session.userID);
  console.log(req.body.listID);
  response = await response.findById(req.body.listID).exec();

  
  response.entries.map((elem, index)=> {
    console.log(elem.id + req.body.entryID);
    if(elem._id == req.body.entryID) {
      
      response.entries.splice(index, 1);
      exit;
    }
  });
  
  await response.save();

  const filePath = "./public/images/entryImages/" + req.body.entryID + ".png";
  fs.unlink(filePath, (err) => {
    if (err) {
      console.error(`Error deleting file: ${err}`);
    } else {
      res.status(204)
    }
  
    //console.log("Entry: ");
  })
  res.send("Deleted")
  //res.redirect(`http://localhost:5173/list/${req.body.listID}`)
  //console.log("Entry: ");
}
)

app.post("/deleteList", async(req,res)=> {

  //console.log(req.body)

  let response = mongoose.model(req.session.user.email, ListSchema, req.session.user.email);
  let list = await response.findById(req.body.listID).exec();
  
  //console.log(list.thumbnail);

  if(list.thumbnail != "default") {
    const filePath = "./public/images/" + req.body.listID + ".png";
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error(`Error deleting file: ${err}`);
      } else {
        console.log("List Thumbnail Deleted")
      }
     
      //console.log("Entry: ");
    })
  }
  try {
  await response.deleteOne({ _id: req.body.listID }).exec();
  res.status(200).send("Deleted Successfully")
  }
  catch(error) {
    res.status(404).send("List not found");
  }





})


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
